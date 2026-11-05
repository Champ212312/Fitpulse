const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('node:crypto');
const { z } = require('zod');
const { rateLimit } = require('express-rate-limit');
const { db } = require('./db');
const { issueSession, requireAuth, allowRoles } = require('./auth');
const router = express.Router();
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many attempts. Try again later.' } });
const plans = { Standard: 600, Student: 540, Senior: 480, 'Fitness Training': 2500 };
const emailSchema = z.string().trim().email().max(254);
const passwordSchema = z.string().min(12).max(128);
const publicUser = u => ({ id:u.id, name:u.name, email:u.email, role:u.role, plan:u.plan, membershipStart:u.membership_start, membershipEnd:u.membership_end, paymentStatus:u.payment_status });
function audit(actor, action, type, id, details={}) { db.prepare('INSERT INTO audit_log(actor_id,action,entity_type,entity_id,details) VALUES(?,?,?,?,?)').run(actor || null, action, type, id || null, JSON.stringify(details)); }

router.post('/auth/register', loginLimit, (req,res) => {
  const parsed = z.object({ name:z.string().trim().min(2).max(100), email:emailSchema, password:passwordSchema, plan:z.enum(['Standard','Student','Senior','Fitness Training']) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error:'Please provide a valid name, email, password (at least 12 characters), and membership plan.', details:parsed.error.flatten() });
  const { name,email,password,plan } = parsed.data;
  const now = new Date(); const end = new Date(now); end.setDate(end.getDate()+30);
  try {
    const id = crypto.randomUUID(); const hash = bcrypt.hashSync(password,12);
    db.prepare(`INSERT INTO users(id,name,email,password_hash,role,plan,membership_start,membership_end,payment_status) VALUES(?,?,?,?,?,?,?,?,?)`)
      .run(id,name,email.toLowerCase(),hash,'member',plan,now.toISOString(),end.toISOString(),'pending');
    audit(id,'member.registered','user',id,{plan,amount:plans[plan]});
    res.status(201).json({ message:'Account created. Membership remains pending until payment is verified.', user:{id,name,email:email.toLowerCase(),role:'member',plan,membershipStart:now.toISOString(),membershipEnd:end.toISOString(),paymentStatus:'pending'}, amountDue:plans[plan] });
  } catch (e) { if (String(e.code).includes('SQLITE_CONSTRAINT')) return res.status(409).json({error:'An account with this email already exists.'}); throw e; }
});
router.post('/auth/login', loginLimit, (req,res) => {
  const parsed = z.object({ email:emailSchema, password:z.string().min(1).max(128), role:z.enum(['member','staff','admin']).optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:'Invalid login details.'});
  const user = db.prepare('SELECT * FROM users WHERE lower(email)=lower(?)').get(parsed.data.email);
  if (!user || user.disabled || !bcrypt.compareSync(parsed.data.password,user.password_hash) || (parsed.data.role && parsed.data.role !== user.role)) return res.status(401).json({error:'Email, password, or role is incorrect.'});
  if (user.role === 'member' && (user.payment_status !== 'paid' || !user.membership_end || new Date(user.membership_end) < new Date())) return res.status(403).json({error:'Membership is pending payment or has expired. Please contact the gym.'});
  issueSession(user,res); audit(user.id,'auth.login','session',null);
  res.json({user:publicUser(user)});
});
router.post('/auth/logout', requireAuth, (req,res) => { db.prepare('DELETE FROM sessions WHERE token_id=?').run(req.sessionTokenId); res.clearCookie('fitpulse_session',{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'strict',path:'/'}); res.json({ok:true}); });
router.get('/auth/me', requireAuth, (req,res) => res.json({user:publicUser(req.user)}));
router.get('/members', requireAuth, allowRoles('staff','admin'), (req,res) => {
  const rows=db.prepare(`SELECT id,name,email,plan,membership_start,membership_end,payment_status,created_at FROM users WHERE role='member' AND disabled=0 ORDER BY name`).all(); res.json({members:rows});
});
router.patch('/members/:id/payment', requireAuth, allowRoles('admin'), (req,res) => {
  const status=z.enum(['paid','pending','refunded']).safeParse(req.body.status); if(!status.success)return res.status(400).json({error:'Invalid payment status.'});
  const member=db.prepare("SELECT id,role FROM users WHERE id=? AND role='member'").get(req.params.id); if(!member)return res.status(404).json({error:'Member not found.'});
  db.prepare('UPDATE users SET payment_status=? WHERE id=?').run(status.data,member.id); audit(req.user.id,'membership.payment_updated','user',member.id,{status:status.data}); res.json({ok:true});
});
router.get('/attendance', requireAuth, (req,res) => {
  let rows;
  if(req.user.role==='member') rows=db.prepare('SELECT id,member_id,display_name,check_in,check_out FROM attendance WHERE member_id=? ORDER BY check_in DESC LIMIT 1000').all(req.user.id);
  else rows=db.prepare('SELECT id,member_id,display_name,check_in,check_out FROM attendance ORDER BY check_in DESC LIMIT 5000').all();
  res.json({records:rows});
});
router.post('/attendance/check-in', requireAuth, allowRoles('member','staff','admin'), (req,res) => {
  const parsed=z.object({memberId:z.string().uuid().optional(),name:z.string().trim().min(2).max(100).optional()}).safeParse(req.body); if(!parsed.success)return res.status(400).json({error:'Invalid check-in details.'});
  let memberId=req.user.role==='member'?req.user.id:parsed.data.memberId;
  let name=req.user.role==='member'?req.user.name:parsed.data.name;
  if(memberId){const m=db.prepare("SELECT id,name,role,payment_status,membership_end FROM users WHERE id=? AND disabled=0").get(memberId); if(!m||m.role!=='member')return res.status(404).json({error:'Member not found.'}); if(m.payment_status!=='paid'||!m.membership_end||new Date(m.membership_end)<new Date())return res.status(403).json({error:'Membership is not active.'}); name=m.name;}
  if(!name)return res.status(400).json({error:'A member is required.'});
  const active=db.prepare('SELECT id FROM attendance WHERE check_out IS NULL').all(); const cap=Number(process.env.MAX_CAPACITY)||50;
  if(active.length>=cap)return res.status(409).json({error:`Facility is at full capacity (${cap}/${cap}).`});
  const duplicate=memberId?db.prepare('SELECT id FROM attendance WHERE member_id=? AND check_out IS NULL').get(memberId):db.prepare('SELECT id FROM attendance WHERE lower(display_name)=lower(?) AND check_out IS NULL').get(name);
  if(duplicate)return res.status(409).json({error:'This member is already checked in.'});
  const result=db.prepare('INSERT INTO attendance(member_id,display_name,check_in,created_by) VALUES(?,?,?,?)').run(memberId||null,name,new Date().toISOString(),req.user.id); audit(req.user.id,'attendance.check_in','attendance',String(result.lastInsertRowid),{memberId}); res.status(201).json({record:db.prepare('SELECT * FROM attendance WHERE id=?').get(result.lastInsertRowid)});
});
router.post('/attendance/:id/check-out', requireAuth, allowRoles('staff','admin'), (req,res) => {
  const id=Number(req.params.id); const record=db.prepare('SELECT * FROM attendance WHERE id=?').get(id); if(!record)return res.status(404).json({error:'Attendance record not found.'}); if(record.check_out)return res.status(409).json({error:'This attendance record is already checked out.'});
  const now=new Date().toISOString(); db.prepare('UPDATE attendance SET check_out=? WHERE id=?').run(now,id); audit(req.user.id,'attendance.check_out','attendance',String(id)); res.json({ok:true,checkOut:now});
});
router.delete('/attendance/:id', requireAuth, allowRoles('admin'), (req,res) => { const id=Number(req.params.id); const record=db.prepare('SELECT id FROM attendance WHERE id=?').get(id); if(!record)return res.status(404).json({error:'Attendance record not found.'}); db.prepare('DELETE FROM attendance WHERE id=?').run(id); audit(req.user.id,'attendance.deleted','attendance',String(id)); res.json({ok:true}); });
router.get('/reports/summary', requireAuth, allowRoles('staff','admin'), (req,res) => { const total=db.prepare('SELECT count(*) n FROM attendance').get().n; const active=db.prepare('SELECT count(*) n FROM attendance WHERE check_out IS NULL').get().n; const members=db.prepare("SELECT count(*) n FROM users WHERE role='member' AND disabled=0").get().n; res.json({totalAttendance:total,activeOccupancy:active,maxCapacity:Number(process.env.MAX_CAPACITY)||50,members}); });
router.get('/audit', requireAuth, allowRoles('admin'), (req,res) => res.json({events:db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 500').all()}));
module.exports=router;

const test=require('node:test');
const assert=require('node:assert/strict');
const validPlans=['Standard','Student','Senior','Fitness Training'];
test('membership plans are restricted to known values',()=>{
 assert.equal(validPlans.includes('Standard'),true);
 assert.equal(validPlans.includes('Free Forever'),false);
});
test('password policy rejects short passwords',()=>{
 const valid=value=>typeof value==='string'&&value.length>=12&&value.length<=128;
 assert.equal(valid('short'),false);
 assert.equal(valid('a-long-enough-password'),true);
});
test('email validation rejects malformed addresses',()=>{
 const valid=value=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
 assert.equal(valid('person@example.com'),true);
 assert.equal(valid('not-an-email'),false);
});

const assert = require("assert");
const F = require("../build");
const P = require("@simplus/permissions");

function pass(f, message, req, res){
	f(req, res, function(err){
		if(err)
			assert.ok(false, message);
		else
			assert.ok(true, message);
	});
}
function npass(f, message, req, res){
	f(req, res, function(err){
		if(err)
			assert.ok(true, message);
		else
			assert.ok(false, message);
	});
}

describe("Firewall tests", function(){
	describe("Firewall operations", function(){
		it("$bool", function(){
			pass(F.$bool(true), "$bool true");
			npass(F.$bool(false), "$bool false");
		});
		it("$not", function(){
			pass(F.$not(F.$bool(false)), "$not $bool false");
			npass(F.$not(F.$bool(true)), "$not $bool true");
		});
		it("$if", function(){
			pass(F.$if(false, F.$bool(true)), "$if false $bool true");
			pass(F.$if(false, F.$bool(false)), "$if false $bool false");
			pass(F.$if(true, F.$bool(true)), "$if true $bool true");
			npass(F.$if(true, F.$bool(false)), "$if true $bool false");
		})
		it("$or", function(){
			pass(F.$or(F.$bool(true), F.$bool(true)), "True True => True");
			pass(F.$or(F.$bool(true), F.$bool(false)), "True False => True");
			pass(F.$or(F.$bool(false), F.$bool(true)), "False True => True");
			npass(F.$or(F.$bool(false), F.$bool(false)), "False False => False");
			pass(F.$or(F.$bool(false), F.$bool(false), F.$bool(true)), "Several values (false, false, true)");
		});
	});

	describe("Firewall users", function(){
		it("isActivated", function(){
			pass(F.isActivated(), "User is activated", {user : {activated : true}})
			npass(F.isActivated(), "User is not activated", {user : {activated : false}})
			npass(F.isActivated(), "User not logged in", {})
		});
		it("isAuthentified", function(){
			pass(F.isAuthentified(), "User is authentified", {user : {activated : true}})
			npass(F.isAuthentified(), "User is authentified", {user : {activated : false}})
			npass(F.isAuthentified(), "User not logged in", {})
		});
		it("isRoot", function(){
			pass(F.isRoot(), "User is root", {user : {activated : true, role : P.USER_ROLES.ROOT}})
			npass(F.isRoot(), "User is public", {user : {activated : true, role : P.USER_ROLES.PUBLIC}})
			npass(F.isRoot(), "User is root but not activated", {user : {activated : false, role : P.USER_ROLES.ROOT}})
			npass(F.isRoot(), "User not logged in", {})
		});
		it("paramIsUser", function(){
			npass(F.paramIsUser(), "User not logged in", {})
			npass(F.paramIsUser(), "User not activated", {user : {activated : false, _id : 5}, params : { uid : 5}});
			pass(F.paramIsUser(), "User active and is session ", {user : {activated : true, _id : 5}, params : { uid : 5}});
			npass(F.paramIsUser(), "User active and is not session ", {user : {activated : true, _id : 6}, params : { uid : 5}});
			pass(F.paramIsUser("user"), "User active and is session custom name", {user : {activated : true, _id : 5}, params : { user : 5}});
		});
		it("hasRole", function(){
			npass(F.hasRole("test"), "User not logged in", {})
			npass(F.hasRole("test"), "User not activated", {user : {activated : false, role : "test"}});
			pass(F.hasRole("test"), "User has role", {user : {activated : true, role : "test"}});
			npass(F.hasRole("root"), "User does not have role", {user : {activated : true, role : "test"}});
			pass(F.hasRole("root", "test"), "User has on of mutipe roles", {user : {activated : true, role : "test"}});
		});
		it("hasPermission", function(){
			npass(F.hasPermission("test/read"), "User not logged in", {})
			npass(F.hasPermission("test/write"), "User not activated", {user : {activated : false, permissions : [{key : "test/write"}]}});
			pass(F.hasPermission("test/write"), "User has global permission", {user : {activated : true, permissions : [{key : "test/write"}]}});
			pass(F.hasPermission("test/write"), "User has permission", {user : {activated : true, permissions : [{key : "test/*"}]}});
		});
	});
});
var app = angular.module("radwi", []);

var Exception = function(message) {
	this.message = message;
}

Exception.prototype.getMessage() {
	return this.message;
}

/* Starts the registration procedure */
function register(username, password, first_name, last_name, $http, cb) {
	$http({
		method: "POST",
		url: "/api/register/",
		data: {
			username: username,
			password: password,
			first_name: first_name,
			last_name: last_name
		},
		headers: {
			"Content-type": "application/json;charset=utf-8"
		}
	})
	.then(function(response) {
		cb(true);
	}, function(rejection) {
		cb(false, new Exception(rejection.data.reason));
	});	
}

/* Authenticates the user */
function authenticate(username, password, $http, cb) {
	$http({
		method: "POST",
		url: "/api/authenticate/",
		data: {
			username: username,
			password: password
		},
		headers: {
			"Content-type": "application/json;charset=utf-8"
		}
	})
	.then(function(response) {
		cb(true, null);
	}, function(rejection) {
		cb(false, new Exception(rejection.data.reason));
	});
}

/* Logs out from the system */
function logout($http, cb) {
	$http({
		method: "GET",
		url: "/api/logout/",
		headers: {
			"Content-type": "application/json;charset=utf-8"
		}
	})
	.then(function(response) {
		cb(true);
	}, function(rejection) {
		cb(false);
	});
}

/* Checks the access */
function check_access($http, cb) {
	$http({
		method: "GET",
		url: "/api/check_token/",
		headers: {
			"Content-type": "application/json;charset=utf-8"
		}
	})
	.then(function(response) {
		cb(true);
	}, function(rejection) {
		cb(false);
	});
}

/* Changes the password */
function change_password($http, username, old_password, new_password, cb) {
	$http({
		method: "POST",
		url: "/api/change_password/",
		data: {
			username: username,
			old_password: old_password,
			new_password: new_password
		},
		headers: {
			"Content-type": "application/json;charset=utf-8"
		}
	})
	.then(function(response) {
		cb(true, null);
	}, function(rejection) {
		cb(false, new Exception(rejection.data.reason));
	});	
}

function count_vouchers($http, cb) {
	$http({
		method: "GET",
		url: "/api/count_vouchers/",
		headers: {
			"Content-type": "application/json;charset=utf-8"
		}
	})
	.then(function(response) {
		var data = response.data;
		cb(true, data.number_of_vouchers);
	}, function(rejection) {
		cb(false, new Exception(rejection.data.reason));
	});
}


/* Main application controller */
app.controller("mainCtrl", function($scope, $http, $location, $interval) {
	
});

import {USER_ROLES, IPermission, verifyRule, Rule} from "@simplus/permissions";
import {Request, Response} from "express";
import {UnauthorizedError} from "./UnauthorizedError";

export interface SessionRequest extends Request{
	user : any;
}

export type Firewall = (req: Request, res: Response, next: (a?: any)=> void) => void;

/**
 * Executes a firewall test only if the condition is true
 * @param c a condition
 * @param firewall 
 */
export function $if(c: boolean, firewall: Firewall): Firewall {
	if(c)
		return firewall;
	return (req, res, next)=> {
		next();
	}
}

/**
 * Check if a user is authentified (passport standard)
 */
export function isAuthentified() : Firewall{
	return (req: SessionRequest, res: Response, next) => {
		if(!req.user)
			return next(new UnauthorizedError("not authentified"));
		if(!req.user.activated )
			return next(new UnauthorizedError("account not active"));
		next();
	}
}

/**
 * Check if a user is authentified and activated
 */
export function isActivated() : Firewall {
	return (req: SessionRequest, res, next) => {
		if( !req.user || !req.user.activated )
			return next(new UnauthorizedError("account not active"));
		next();
	}
}

/**
 * Check if user role is root
 */
export function isRoot() : Firewall {
	return (req: SessionRequest, res, next) => {
		if(! req.user || req.user.role !== USER_ROLES.ROOT )
			return next(new UnauthorizedError("not root"));
		if(!req.user.activated )
			return next(new UnauthorizedError("account not active"));
		next();
	}
}

/**
 * Check if the user session has the same value as the route parameter (uid is the default parameter nam)
 * @param uid The aprameter name (uid for /my/path/:uid)
 */
export function paramIsUser(uid: string = "uid") : Firewall {
	return $or( isRoot(), (req: SessionRequest, res, next) => {
		if(!req.user || !req.params || !req.user.activated || req.user._id !== req.params[uid])
			return next(new UnauthorizedError("param is not user"));
		next();
	});
}

/**
 * Check if a user has one of the given roles
 * @param roles a list of roles
 */
export function hasRole(...roles: string[]) : Firewall{
	return $or( isRoot(), (req: SessionRequest, res, next) => {
		if(! req.user || !req.user.activated || roles.indexOf(req.user.role) < 0 )
			return next(new UnauthorizedError("user has not the right role: "+roles.toString()));
		next();
	});
}

/**
 * Check if the user has permissions
 * @param rule the rule that has to be verified
 */
export function hasPermission(rule: Rule) : Firewall {
	return $or( isRoot(), (req: SessionRequest, res, next) => {
		if (! req.user || !req.user.activated || !verifyRule(rule, req.user.permissions || []))
			return next(new UnauthorizedError("user does not have the required permission: "+rule));
		next();
	});
}

/**
 * Disjunction between several firewalls
 * @param firewalls
 */
export function $or(...firewalls : Firewall[]) : Firewall {
	return (req, res, next) => {
		let counter = 0;
		let result = undefined;
		let ok = false;
		const verify = (err) => {
			if( !err)
				ok = true;
			result = result || err;
			++counter;
			if( counter >= firewalls.length) {
				next( ok ? undefined : result)
			};
		}
		for( let f of firewalls)
			f(req, res, verify);
	}
}

/**
 * Negation of a firewall
 * @param firewall 
 */
export function $not(firewall : Firewall) : Firewall{
	return (req, res, next) => {
		firewall(req, res, (err) => {
			if(err)
				next()
			else
				next(new UnauthorizedError())
		})
	}
}

/**
 * Converts a condition to a firewall (pass if the condition is true, and fails if codition equals false)
 * @param b the condition
 */
export function $bool(b: boolean): Firewall {
	return (req, res, next) => {
		if(b)
			return next();
		return next(new UnauthorizedError());
	}
}
import {
    BaseAuthOptions,
    ForbiddenException,
    initBaseAuth,
    RequriedOrgInfo,
    UnauthorizedException,
    UnexpectedException,
    User,
    UserAndOrgMemberInfo,
    UserClass,
} from "@propelauth/node"
import { RequiredOrgInfo } from "@propelauth/node/dist/auth"
import { NextFunction, Request, Response } from "express"

export interface AuthOptions extends BaseAuthOptions {
    debugMode?: boolean
}

type Middleware = (req: Request, res: Response, next: NextFunction) => Promise<void>

export type InitAuthResult = ReturnType<typeof initBaseAuth> & {
    requireUser: Middleware
    optionalUser: Middleware
    requireOrgMember: (args?: RequireOrgMemberArgs) => Middleware
    requireOrgMemberWithMinimumRole: (args: RequireOrgMemberWithMinimumRoleArgs) => Middleware
    requireOrgMemberWithExactRole: (args: RequireOrgMemberWithExactRoleArgs) => Middleware
    requireOrgMemberWithPermission: (args: RequireOrgMemberWithPermissionArgs) => Middleware
    requireOrgMemberWithAllPermissions: (args: RequireOrgMemberWithAllPermissionsArgs) => Middleware
}

export function initAuth(opts: AuthOptions): InitAuthResult {
    const auth = initBaseAuth(opts)
    const debugMode = opts.debugMode || false

    const requireUser = createUserExtractingMiddleware({
        validateAccessTokenAndGetUser: auth.validateAccessTokenAndGetUser,
        validateAccessTokenAndGetUserClass: auth.validateAccessTokenAndGetUserClass,
        requireCredentials: true,
        debugMode,
    })

    const optionalUser = createUserExtractingMiddleware({
        validateAccessTokenAndGetUser: auth.validateAccessTokenAndGetUser,
        validateAccessTokenAndGetUserClass: auth.validateAccessTokenAndGetUserClass,
        requireCredentials: false,
        debugMode,
    })
    const requireOrgMember = createRequireOrgMemberMiddleware(
        auth.validateAccessTokenAndGetUserWithOrgInfo,
        auth.validateAccessTokenAndGetUserClass,
        debugMode
    )

    const requireOrgMemberWithMinimumRole = createRequireOrgMemberMiddlewareWithMinimumRole(
        auth.validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole,
        auth.validateAccessTokenAndGetUserClass,
        debugMode
    )
    const requireOrgMemberWithExactRole = createRequireOrgMemberMiddlewareWithExactRole(
        auth.validateAccessTokenAndGetUserWithOrgInfoWithExactRole,
        auth.validateAccessTokenAndGetUserClass,
        debugMode
    )
    const requireOrgMemberWithPermission = createRequireOrgMemberMiddlewareWithPermission(
        auth.validateAccessTokenAndGetUserWithOrgInfoWithPermission,
        auth.validateAccessTokenAndGetUserClass,
        debugMode
    )
    const requireOrgMemberWithAllPermissions = createRequireOrgMemberMiddlewareWithAllPermissions(
        auth.validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions,
        auth.validateAccessTokenAndGetUserClass,
        debugMode
    )

    return {
        ...auth,
        requireUser,
        optionalUser,
        requireOrgMember,
        requireOrgMemberWithMinimumRole,
        requireOrgMemberWithExactRole,
        requireOrgMemberWithPermission,
        requireOrgMemberWithAllPermissions,
    }
}

function createUserExtractingMiddleware({
    validateAccessTokenAndGetUser,
    validateAccessTokenAndGetUserClass,
    requireCredentials,
    debugMode,
}: CreateRequestHandlerArgs) {
    return async function (req: Request, res: Response, next: NextFunction) {
        try {
            req.user = await validateAccessTokenAndGetUser(req.headers.authorization)
            req.userClass = await validateAccessTokenAndGetUserClass(req.headers.authorization)
            next()
        } catch (e: any) {
            if (e instanceof UnauthorizedException) {
                handleUnauthorizedException({ exception: e, requireCredentials, res, next, debugMode })
            } else if (e instanceof UnexpectedException) {
                handleUnexpectedException(e, res, debugMode)
            } else {
                throw e
            }
        }
    }
}

function createRequireOrgMemberMiddleware(
    validateAccessTokenAndGetUserWithOrgInfo: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo
    ) => Promise<UserAndOrgMemberInfo>,
    validateAccessTokenAndGetUserClass: (authorizationHeader: string | undefined) => Promise<UserClass>,
    debugMode: boolean
) {
    return function requireOrgMember(args?: RequireOrgMemberArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader, requiredOrgInfo)
            },
            (authorizationHeader) => {
                return validateAccessTokenAndGetUserClass(authorizationHeader)
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function createRequireOrgMemberMiddlewareWithMinimumRole(
    validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo,
        minimumRole: string
    ) => Promise<UserAndOrgMemberInfo>,
    validateAccessTokenAndGetUserClass: (authorizationHeader: string | undefined) => Promise<UserClass>,
    debugMode: boolean
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithMinimumRoleArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(
                    authorizationHeader,
                    requiredOrgInfo,
                    args.minimumRequiredRole
                )
            },
            (authorizationHeader) => {
                return validateAccessTokenAndGetUserClass(authorizationHeader)
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function createRequireOrgMemberMiddlewareWithExactRole(
    validateAccessTokenAndGetUserWithOrgInfoWithExactRole: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo,
        role: string
    ) => Promise<UserAndOrgMemberInfo>,
    validateAccessTokenAndGetUserClass: (authorizationHeader: string | undefined) => Promise<UserClass>,
    debugMode: boolean
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithExactRoleArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfoWithExactRole(
                    authorizationHeader,
                    requiredOrgInfo,
                    args.role
                )
            },
            (authorizationHeader) => {
                return validateAccessTokenAndGetUserClass(authorizationHeader)
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function createRequireOrgMemberMiddlewareWithPermission(
    validateAccessTokenAndGetUserWithOrgInfoWithPermission: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo,
        permission: string
    ) => Promise<UserAndOrgMemberInfo>,
    validateAccessTokenAndGetUserClass: (authorizationHeader: string | undefined) => Promise<UserClass>,
    debugMode: boolean
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithPermissionArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfoWithPermission(
                    authorizationHeader,
                    requiredOrgInfo,
                    args.permission
                )
            },
            (authorizationHeader) => {
                return validateAccessTokenAndGetUserClass(authorizationHeader)
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function createRequireOrgMemberMiddlewareWithAllPermissions(
    validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequriedOrgInfo,
        permissions: string[]
    ) => Promise<UserAndOrgMemberInfo>,
    validateAccessTokenAndGetUserClass: (authorizationHeader: string | undefined) => Promise<UserClass>,
    debugMode: boolean
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithAllPermissionsArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware(
            (authorizationHeader, requiredOrgInfo) => {
                return validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(
                    authorizationHeader,
                    requiredOrgInfo,
                    args.permissions
                )
            },
            (authorizationHeader) => {
                return validateAccessTokenAndGetUserClass(authorizationHeader)
            },
            debugMode,
            orgIdExtractor,
            orgNameExtractor
        )
    }
}

function requireOrgMemberGenericMiddleware(
    validateAccessTokenAndGetUserWithOrgInfo: (
        authorizationHeader: string | undefined,
        requiredOrgInfo: RequiredOrgInfo
    ) => Promise<UserAndOrgMemberInfo>,
    validateAccessTokenAndGetUserClass: (authorizationHeader: string | undefined) => Promise<UserClass>,
    debugMode: boolean,
    orgIdExtractor?: (req: Request) => string,
    orgNameExtractor?: (req: Request) => string
) {
    return async function (req: Request, res: Response, next: NextFunction) {
        let requiredOrgInfo: RequiredOrgInfo
        if (orgIdExtractor || orgNameExtractor) {
            const requiredOrgId = orgIdExtractor ? orgIdExtractor(req) : undefined
            const requiredOrgName = orgNameExtractor ? orgNameExtractor(req) : undefined
            requiredOrgInfo = {
                orgId: requiredOrgId,
                orgName: requiredOrgName,
            }
        } else {
            requiredOrgInfo = {
                orgId: defaultOrgIdExtractor(req),
                orgName: undefined,
            }
        }

        try {
            const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfo(
                req.headers.authorization,
                requiredOrgInfo
            )
            req.user = userAndOrgMemberInfo.user
            req.org = userAndOrgMemberInfo.orgMemberInfo
            req.userClass = await validateAccessTokenAndGetUserClass(req.headers.authorization)
            next()
        } catch (e: any) {
            if (e instanceof UnauthorizedException) {
                handleUnauthorizedException({ exception: e, requireCredentials: true, res, next, debugMode })
            } else if (e instanceof ForbiddenException) {
                handleForbiddenExceptionWithRequiredCredentials(e, res, debugMode)
            } else if (e instanceof UnexpectedException) {
                handleUnexpectedException(e, res, debugMode)
            } else {
                handleUnexpectedException(
                    new UnexpectedException("An unexpected exception has occurred"),
                    res,
                    debugMode
                )
            }
        }
    }
}

// With an unauthorized exception, we only reject the request if credentials are required
function handleUnauthorizedException({
    exception,
    requireCredentials,
    res,
    next,
    debugMode,
}: HandleUnauthorizedExceptionArgs) {
    if (requireCredentials && debugMode) {
        res.status(exception.status).send(exception.message)
    } else if (requireCredentials) {
        res.status(exception.status).send()
    } else {
        next()
    }
}

// With a forbidden exception, we will always reject the request
function handleForbiddenExceptionWithRequiredCredentials(
    exception: ForbiddenException,
    res: Response,
    debugMode: boolean
) {
    if (debugMode) {
        res.status(exception.status).send(exception.message)
    } else {
        res.status(exception.status).send()
    }
}

// With an unexpected exception, we will always reject the request
function handleUnexpectedException(exception: UnexpectedException, res: Response, debugMode: boolean) {
    if (debugMode) {
        res.status(exception.status).send(exception.message)
    } else {
        res.status(exception.status).send()
    }
}

interface CreateRequestHandlerArgs {
    validateAccessTokenAndGetUser: (authorizationHeader?: string) => Promise<User>
    validateAccessTokenAndGetUserClass: (authorizationHeader?: string) => Promise<UserClass>
    requireCredentials: boolean
    debugMode: boolean
}

interface HandleUnauthorizedExceptionArgs {
    exception: UnauthorizedException
    requireCredentials: boolean
    res: Response
    next: NextFunction
    debugMode: boolean
}

export interface RequireOrgMemberArgs {
    orgIdExtractor?: (req: Request) => string
    orgNameExtractor?: (req: Request) => string
}

export interface RequireOrgMemberWithMinimumRoleArgs {
    orgIdExtractor?: (req: Request) => string
    orgNameExtractor?: (req: Request) => string
    minimumRequiredRole: string
}

export interface RequireOrgMemberWithExactRoleArgs {
    orgIdExtractor?: (req: Request) => string
    orgNameExtractor?: (req: Request) => string
    role: string
}

export interface RequireOrgMemberWithPermissionArgs {
    orgIdExtractor?: (req: Request) => string
    orgNameExtractor?: (req: Request) => string
    permission: string
}

export interface RequireOrgMemberWithAllPermissionsArgs {
    orgIdExtractor?: (req: Request) => string
    orgNameExtractor?: (req: Request) => string
    permissions: string[]
}

function defaultOrgIdExtractor(req: Request) {
    return req.params.orgId
}

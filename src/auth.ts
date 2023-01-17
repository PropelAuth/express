import {NextFunction, Request, Response} from "express"
import {
    BaseAuthOptions, ForbiddenException,
    initBaseAuth,
    RequriedOrgInfo,
    UnauthorizedException,
    UnexpectedException, UserAndOrgMemberInfo, User
} from "@propelauth/node";
import {RequiredOrgInfo} from "@propelauth/node/dist/auth";

export function initAuth(opts: BaseAuthOptions) {
    const auth = initBaseAuth(opts)

    // Create middlewares
    const requireUser = createUserExtractingMiddleware({
        validateAccessTokenAndGetUser: auth.validateAccessTokenAndGetUser,
        requireCredentials: true,
    })
    const optionalUser = createUserExtractingMiddleware({
        validateAccessTokenAndGetUser: auth.validateAccessTokenAndGetUser,
        requireCredentials: false,
    })
    const requireOrgMember = createRequireOrgMemberMiddleware(auth.validateAccessTokenAndGetUserWithOrgInfo)
    const requireOrgMemberWithMinimumRole = createRequireOrgMemberMiddlewareWithMinimumRole(auth.validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole)
    const requireOrgMemberWithExactRole = createRequireOrgMemberMiddlewareWithExactRole(auth.validateAccessTokenAndGetUserWithOrgInfoWithExactRole)
    const requireOrgMemberWithPermission = createRequireOrgMemberMiddlewareWithPermission(auth.validateAccessTokenAndGetUserWithOrgInfoWithPermission)
    const requireOrgMemberWithAllPermissions = createRequireOrgMemberMiddlewareWithAllPermissions(auth.validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions)

    return {
        requireUser,
        optionalUser,
        requireOrgMember,
        requireOrgMemberWithMinimumRole,
        requireOrgMemberWithExactRole,
        requireOrgMemberWithPermission,
        requireOrgMemberWithAllPermissions,
        fetchUserMetadataByUserId: auth.fetchUserMetadataByUserId,
        fetchUserMetadataByEmail: auth.fetchUserMetadataByEmail,
        fetchUserMetadataByUsername: auth.fetchUserMetadataByUsername,
        fetchBatchUserMetadataByUserIds: auth.fetchBatchUserMetadataByUserIds,
        fetchBatchUserMetadataByEmails: auth.fetchBatchUserMetadataByEmails,
        fetchBatchUserMetadataByUsernames: auth.fetchBatchUserMetadataByUsernames,
        fetchOrg: auth.fetchOrg,
        fetchOrgByQuery: auth.fetchOrgByQuery,
        fetchUsersByQuery: auth.fetchUsersByQuery,
        fetchUsersInOrg: auth.fetchUsersInOrg,
        createUser: auth.createUser,
        updateUserMetadata: auth.updateUserMetadata,
        updateUserEmail: auth.updateUserEmail,
        updateUserPassword: auth.updateUserPassword,
        createMagicLink: auth.createMagicLink,
        migrateUserFromExternalSource: auth.migrateUserFromExternalSource,
        disableUser2fa: auth.disableUser2fa,
        createOrg: auth.createOrg,
        addUserToOrg: auth.addUserToOrg,
        deleteUser: auth.deleteUser,
        disableUser: auth.disableUser,
        enableUser: auth.enableUser,
        changeUserRoleInOrg: auth.changeUserRoleInOrg,
        removeUserFromOrg: auth.removeUserFromOrg,
        updateOrg: auth.updateOrg,
        deleteOrg: auth.deleteOrg,
        allowOrgToSetupSamlConnection: auth.allowOrgToSetupSamlConnection,
        disallowOrgToSetupSamlConnection: auth.disallowOrgToSetupSamlConnection,
    }
}

function createUserExtractingMiddleware({
                                            validateAccessTokenAndGetUser,
                                            requireCredentials,
                                        }: CreateRequestHandlerArgs) {
    return async function (req: Request, res: Response, next: NextFunction) {
        try {
            req.user = await validateAccessTokenAndGetUser(req.headers.authorization)
            next()
        } catch (e: any) {
            if (e instanceof UnauthorizedException) {
                handleUnauthorizedException({exception: e, requireCredentials, res, next})
            } else if (e instanceof UnexpectedException) {
                handleUnexpectedException(e, res)
            } else {
                throw e
            }
        }
    }
}

function createRequireOrgMemberMiddleware(
    validateAccessTokenAndGetUserWithOrgInfo: (authorizationHeader: string | undefined,
                                               requiredOrgInfo: RequriedOrgInfo) => Promise<UserAndOrgMemberInfo>,
) {
    return function requireOrgMember(args?: RequireOrgMemberArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware((authorizationHeader, requiredOrgInfo) => {
            return validateAccessTokenAndGetUserWithOrgInfo(authorizationHeader, requiredOrgInfo)
        }, orgIdExtractor, orgNameExtractor)
    }
}

function createRequireOrgMemberMiddlewareWithMinimumRole(
    validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole: (authorizationHeader: string | undefined,
                                                              requiredOrgInfo: RequriedOrgInfo,
                                                              minimumRole: string) => Promise<UserAndOrgMemberInfo>,
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithMinimumRoleArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware((authorizationHeader, requiredOrgInfo) => {
            return validateAccessTokenAndGetUserWithOrgInfoWithMinimumRole(authorizationHeader, requiredOrgInfo, args.minimumRequiredRole)
        }, orgIdExtractor, orgNameExtractor)
    }
}

function createRequireOrgMemberMiddlewareWithExactRole(
    validateAccessTokenAndGetUserWithOrgInfoWithExactRole: (authorizationHeader: string | undefined,
                                                            requiredOrgInfo: RequriedOrgInfo,
                                                            role: string) => Promise<UserAndOrgMemberInfo>,
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithExactRoleArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware((authorizationHeader, requiredOrgInfo) => {
            return validateAccessTokenAndGetUserWithOrgInfoWithExactRole(authorizationHeader, requiredOrgInfo, args.role)
        }, orgIdExtractor, orgNameExtractor)
    }
}

function createRequireOrgMemberMiddlewareWithPermission(
    validateAccessTokenAndGetUserWithOrgInfoWithPermission: (authorizationHeader: string | undefined,
                                                             requiredOrgInfo: RequriedOrgInfo,
                                                             permission: string) => Promise<UserAndOrgMemberInfo>,
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithPermissionArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware((authorizationHeader, requiredOrgInfo) => {
            return validateAccessTokenAndGetUserWithOrgInfoWithPermission(authorizationHeader, requiredOrgInfo, args.permission)
        }, orgIdExtractor, orgNameExtractor)
    }
}

function createRequireOrgMemberMiddlewareWithAllPermissions(
    validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions: (authorizationHeader: string | undefined,
                                                                 requiredOrgInfo: RequriedOrgInfo,
                                                                 permissions: string[]) => Promise<UserAndOrgMemberInfo>,
) {
    return function requireOrgMemberWithMinimumRole(args: RequireOrgMemberWithAllPermissionsArgs) {
        const orgIdExtractor = args ? args.orgIdExtractor : undefined
        const orgNameExtractor = args ? args.orgNameExtractor : undefined

        return requireOrgMemberGenericMiddleware((authorizationHeader, requiredOrgInfo) => {
            return validateAccessTokenAndGetUserWithOrgInfoWithAllPermissions(authorizationHeader, requiredOrgInfo, args.permissions)
        }, orgIdExtractor, orgNameExtractor)
    }
}

function requireOrgMemberGenericMiddleware(
    validateAccessTokenAndGetUserWithOrgInfo: (authorizationHeader: string | undefined, requiredOrgInfo: RequiredOrgInfo) => Promise<UserAndOrgMemberInfo>,
    orgIdExtractor?: (req: Request) => string,
    orgNameExtractor?: (req: Request) => string
) {
    return async function (req: Request, res: Response, next: NextFunction) {
        let requiredOrgInfo: RequiredOrgInfo;
        if (orgIdExtractor || orgNameExtractor) {
            const requiredOrgId = orgIdExtractor ? orgIdExtractor(req) : undefined
            const requiredOrgName = orgNameExtractor ? orgNameExtractor(req) : undefined
            requiredOrgInfo = {
                orgId: requiredOrgId,
                orgName: requiredOrgName,
            };
        } else {
            requiredOrgInfo = {
                orgId: defaultOrgIdExtractor(req),
                orgName: undefined,
            }
        }

        try {
            const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfo(req.headers.authorization, requiredOrgInfo)
            req.user = userAndOrgMemberInfo.user
            req.org = userAndOrgMemberInfo.orgMemberInfo
            next()
        } catch (e: any) {
            if (e instanceof UnauthorizedException) {
                handleUnauthorizedException({exception: e, requireCredentials: true, res, next})
            } else if (e instanceof ForbiddenException) {
                handleForbiddenExceptionWithRequiredCredentials(e, res)
            } else if (e instanceof UnexpectedException) {
                handleUnexpectedException(e, res)
            } else {
                handleUnexpectedException(new UnexpectedException("An unexpected exception has occurred"), res)
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
                                     }: HandleUnauthorizedExceptionArgs) {
    if (requireCredentials) {
        res.status(exception.status).send(exception.message)
    } else {
        next()
    }
}

// With a forbidden exception, we will always reject the request
function handleForbiddenExceptionWithRequiredCredentials(
    exception: ForbiddenException,
    res: Response,
) {
    res.status(exception.status).send(exception.message)
}


// With an unexpected exception, we will always reject the request
function handleUnexpectedException(exception: UnexpectedException, res: Response) {
    res.status(exception.status).send(exception.message)
}

interface CreateRequestHandlerArgs {
    validateAccessTokenAndGetUser: (authorizationHeader?: string) => Promise<User>
    requireCredentials: boolean
}

interface CreateRequestHandlerArgs {
    validateAccessTokenAndGetUser: (authorizationHeader?: string) => Promise<User>
    requireCredentials: boolean
}

interface HandleUnauthorizedExceptionArgs {
    exception: UnauthorizedException
    requireCredentials: boolean
    res: Response
    next: NextFunction
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
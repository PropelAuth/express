import {NextFunction, Request, Response} from "express"
import {
    BaseAuthOptions, ForbiddenException,
    initBaseAuth,
    RequriedOrgInfo,
    UnauthorizedException,
    UnexpectedException, UserAndOrgMemberInfo, UserRole, User
} from "@propelauth/node";

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

    return {
        requireUser,
        optionalUser,
        requireOrgMember,
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
        createMagicLink: auth.createMagicLink,
        UserRole: auth.UserRole,
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
                                               requiredOrgInfo: RequriedOrgInfo,
                                               minimumRequiredRole?: UserRole) => Promise<UserAndOrgMemberInfo>,
) {
    return function requireOrgMember(args?: RequireOrgMemberArgs) {
        const orgIdExtractor = args?.orgIdExtractor;
        const orgNameExtractor = args?.orgNameExtractor;
        const minimumRequiredRole = args?.minimumRequiredRole

        return async function (req: Request, res: Response, next: NextFunction) {
            const requiredOrgId = orgIdExtractor ? orgIdExtractor(req) : undefined
            const requiredOrgName = orgNameExtractor ? orgNameExtractor(req) : undefined
            const requiredOrgInfo: RequriedOrgInfo = {
                orgId: requiredOrgId,
                orgName: requiredOrgName,
            }

            try {
                const userAndOrgMemberInfo = await validateAccessTokenAndGetUserWithOrgInfo(req.headers.authorization, requiredOrgInfo, minimumRequiredRole)
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
    minimumRequiredRole?: UserRole
    orgIdExtractor?: (req: Request) => string
    orgNameExtractor?: (req: Request) => string
}

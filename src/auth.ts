import { NextFunction, Request, Response } from "express"
import jwt, { VerifyOptions } from "jsonwebtoken"
import {
    fetchBatchUserMetadata,
    fetchTokenVerificationMetadata,
    fetchUserMetadataByQuery,
    TokenVerificationMetadata,
} from "./api"
import UnauthorizedException from "./UnauthorizedException"
import UnexpectedException from "./UnexpectedException"
import { InternalUser, toUser, UserMetadata, UserRole } from "./user"
import { validateAuthUrl } from "./validators"
import ForbiddenException from "./ForbiddenException"

export type AuthOptions = {
    debugMode?: boolean
    authUrl: string
    apiKey: string
}

export function initAuth(opts: AuthOptions) {
    const debugMode: boolean = opts.debugMode === undefined ? false : opts.debugMode
    const authUrl: URL = validateAuthUrl(opts.authUrl)
    const apiKey: string = opts.apiKey
    const tokenVerificationMetadataPromise = fetchTokenVerificationMetadata(authUrl, apiKey).catch((err) => {
        console.error("Error initializing auth library. ", err)
    })

    // Create middlewares
    const requireUser = createUserExtractingMiddleware({
        requireCredentials: true,
        debugMode,
        tokenVerificationMetadataPromise,
    })
    const optionalUser = createUserExtractingMiddleware({
        requireCredentials: false,
        debugMode,
        tokenVerificationMetadataPromise,
    })
    const requireOrgMember = createRequireOrgMemberMiddleware(debugMode, requireUser)

    // Utility functions
    function fetchUserMetadataByUserId(userId: string): Promise<UserMetadata | null> {
        return fetchUserMetadataByQuery(authUrl, apiKey, { user_id: userId })
    }

    function fetchUserMetadataByEmail(email: string): Promise<UserMetadata | null> {
        return fetchUserMetadataByQuery(authUrl, apiKey, { email: email })
    }

    function fetchUserMetadataByUsername(username: string): Promise<UserMetadata | null> {
        return fetchUserMetadataByQuery(authUrl, apiKey, { username: username })
    }

    function fetchBatchUserMetadataByUserIds(userIds: string[]): Promise<{ [userId: string]: UserMetadata }> {
        return fetchBatchUserMetadata(authUrl, apiKey, "user_id", userIds)
    }

    function fetchBatchUserMetadataByEmails(emails: string[]): Promise<{ [email: string]: UserMetadata }> {
        return fetchBatchUserMetadata(authUrl, apiKey, "email", emails)
    }

    function fetchBatchUserMetadataByUsernames(usernames: string[]): Promise<{ [username: string]: UserMetadata }> {
        return fetchBatchUserMetadata(authUrl, apiKey, "username", usernames)
    }

    return {
        requireUser,
        optionalUser,
        requireOrgMember,
        fetchUserMetadataByUserId,
        fetchUserMetadataByEmail,
        fetchUserMetadataByUsername,
        fetchBatchUserMetadataByUserIds,
        fetchBatchUserMetadataByEmails,
        fetchBatchUserMetadataByUsernames,
        UserRole,
    }
}

function createUserExtractingMiddleware({
                                            requireCredentials,
                                            debugMode,
                                            tokenVerificationMetadataPromise,
                                        }: CreateRequestHandlerArgs) {
    return async function(req: Request, res: Response, next: NextFunction) {
        try {
            const tokenVerificationMetadata = await getTokenVerificationMetadata(tokenVerificationMetadataPromise)
            const bearerToken = extractBearerToken(req)
            req.user = await verifyToken(bearerToken, tokenVerificationMetadata)
            next()
        } catch (e) {
            if (e instanceof UnauthorizedException) {
                handleUnauthorizedException({ exception: e, requireCredentials, debugMode, res, next })
            } else if (e instanceof UnexpectedException) {
                handleUnexpectedException({ exception: e, debugMode, res })
            } else {
                throw e
            }
        }
    }
}

function createRequireOrgMemberMiddleware(
    debugMode: boolean,
    requireUser: (req: Request, res: Response, next: NextFunction) => void,
) {
    return function requireOrgMember(args?: RequireOrgMemberArgs) {
        // By default, expect the orgId to be passed in as a path parameter
        const orgIdExtractorWithDefault = args?.orgIdExtractor
            ? args.orgIdExtractor
            : (req: Request) => req.params.orgId
        const minimumRequiredRole = args?.minimumRequiredRole
        const validRole = isValidRole(minimumRequiredRole)

        if (!validRole) {
            console.error(
                "Unknown role ",
                minimumRequiredRole,
                ". " +
                "Role must be one of [UserRole.Owner, UserRole.Admin, UserRole.Member] or undefined. " +
                "Requests will be rejected to be safe.",
            )
        }

        return function(req: Request, res: Response, next: NextFunction) {
            // First we call into requireUser to validate the token and set the user
            return requireUser(req, res, () => {
                if (!req.user) {
                    return handleUnauthorizedExceptionWithRequiredCredentials(
                        new UnauthorizedException("No user credentials found for requireOrgMember"),
                        debugMode,
                        res,
                    )
                }

                // Make sure the user is a member of the required org
                const requiredOrgId = orgIdExtractorWithDefault(req)
                const orgIdToOrgMemberInfo = req.user.orgIdToOrgMemberInfo
                if (!orgIdToOrgMemberInfo || !orgIdToOrgMemberInfo.hasOwnProperty(requiredOrgId)) {
                    return handleForbiddenExceptionWithRequiredCredentials(
                        new ForbiddenException(`User is not a member of org ${requiredOrgId}`),
                        debugMode,
                        res,
                    )
                }

                // If minimumRequiredRole is specified, make sure the user is at least that role
                let orgMemberInfo = orgIdToOrgMemberInfo[requiredOrgId]
                if (!validRole) {
                    return handleUnexpectedException({
                        exception: new UnexpectedException(
                            `Configuration error. Minimum required role (${minimumRequiredRole}) is invalid.`,
                        ),
                        debugMode,
                        res,
                    })
                } else if (minimumRequiredRole !== undefined && orgMemberInfo.userRole < minimumRequiredRole) {
                    return handleForbiddenExceptionWithRequiredCredentials(
                        new ForbiddenException(
                            `User's role ${orgMemberInfo.userRole} doesn't meet minimum required role`,
                        ),
                        debugMode,
                        res,
                    )
                }

                req.org = orgMemberInfo
                next()
            })
        }
    }
}

function extractBearerToken(req: Request): string {
    const authHeader = req.header("authorization")
    if (!authHeader) {
        throw new UnauthorizedException("No authorization header found.")
    }

    const authHeaderParts = authHeader.split(" ")
    if (authHeaderParts.length !== 2 || authHeaderParts[0].toLowerCase() !== "bearer") {
        throw new UnauthorizedException("Invalid authorization header. Expected: Bearer {accessToken}")
    }

    return authHeaderParts[1]
}

async function verifyToken(bearerToken: string, tokenVerificationMetadata: TokenVerificationMetadata) {
    const options: VerifyOptions = {
        algorithms: ["RS256"],
        issuer: tokenVerificationMetadata.issuer,
    }
    try {
        const decoded = jwt.verify(bearerToken, tokenVerificationMetadata.verifierKey, options)
        return toUser(<InternalUser>decoded)
    } catch (e: unknown) {
        if (e instanceof Error) {
            throw new UnauthorizedException(e.message)
        } else {
            throw new UnauthorizedException("Unable to decode jwt")
        }
    }
}

// With an unexpected exception, we will always reject the request
function handleUnexpectedException({ exception, debugMode, res }: HandleUnexpectedExceptionArgs) {
    if (debugMode) {
        res.status(exception.status).send(exception.message)
    } else {
        res.status(exception.status).send("Unauthorized")
    }
}

// With an unauthorized exception, we only reject the request if credentials are required
function handleUnauthorizedException({
                                         exception,
                                         requireCredentials,
                                         debugMode,
                                         res,
                                         next,
                                     }: HandleUnauthorizedExceptionArgs) {
    if (requireCredentials) {
        handleUnauthorizedExceptionWithRequiredCredentials(exception, debugMode, res)
    } else {
        next()
    }
}

function handleUnauthorizedExceptionWithRequiredCredentials(
    exception: UnauthorizedException,
    debugMode: boolean,
    res: Response,
) {
    if (debugMode) {
        res.status(exception.status).send(exception.message)
    } else {
        res.status(exception.status).send("Unauthorized")
    }
}

function handleForbiddenExceptionWithRequiredCredentials(
    exception: ForbiddenException,
    debugMode: boolean,
    res: Response,
) {
    if (debugMode) {
        res.status(exception.status).send(exception.message)
    } else {
        res.status(exception.status).send("Unauthorized")
    }
}

async function getTokenVerificationMetadata(
    tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>,
) {
    const tokenVerificationMetadata = await tokenVerificationMetadataPromise
    // If we were unable to fetch the token verification metadata, reject all requests
    if (!tokenVerificationMetadata) {
        const errorMessage = "Auth library not initialized, rejecting request. This is likely a bad API key"
        console.error(errorMessage)
        throw new UnexpectedException(errorMessage)
    }

    return tokenVerificationMetadata
}

function isValidRole(role: UserRole | undefined) {
    return role === undefined || role === UserRole.Owner || role === UserRole.Admin || role === UserRole.Member
}

interface CreateRequestHandlerArgs {
    requireCredentials: boolean
    debugMode: boolean
    tokenVerificationMetadataPromise: Promise<TokenVerificationMetadata | void>
}

interface HandleUnauthorizedExceptionArgs {
    exception: UnauthorizedException
    requireCredentials: boolean
    debugMode: boolean
    res: Response
    next: NextFunction
}

interface HandleUnexpectedExceptionArgs {
    exception: UnexpectedException
    debugMode: boolean
    res: Response
}

export interface RequireOrgMemberArgs {
    minimumRequiredRole?: UserRole
    orgIdExtractor?: (req: Request) => string
}

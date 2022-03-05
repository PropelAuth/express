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
import { InternalUser, toUser, UserMetadata } from "./user"
import { validateAuthUrl } from "./validators"
import ForbiddenException from "./ForbiddenException"

export type AuthOptions = {
    debugMode?: boolean
    authUrl: string
    apiKey: string

    /**
     * By default, this library performs a one-time fetch on startup for
     *   token verification metadata from your authUrl using your apiKey.
     *
     * This is usually preferred to make sure you have the most up to date information,
     *   however, in environments like serverless, this one-time fetch becomes a
     *   per-request fetch.
     *
     * In those environments, you can specify the token verification metadata manually,
     *   which you can obtain from your PropelAuth project.
     */
    manualTokenVerificationMetadata?: TokenVerificationMetadata
}

export function initAuth(opts: AuthOptions) {
    const debugMode: boolean = opts.debugMode === undefined ? false : opts.debugMode
    const authUrl: URL = validateAuthUrl(opts.authUrl)
    const apiKey: string = opts.apiKey
    const tokenVerificationMetadataPromise = fetchTokenVerificationMetadata(
        authUrl, apiKey, opts.manualTokenVerificationMetadata
    ).catch((err) => {
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
            req.roleNameToIndex = tokenVerificationMetadata.roleNameToIndex;
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
    requireUser: (req: Request, res: Response, next: NextFunction) => void
) {
    return function requireOrgMember(args?: RequireOrgMemberArgs) {
        // By default, expect the orgId to be passed in as a path parameter
        const orgIdExtractorWithDefault = args?.orgIdExtractor
            ? args.orgIdExtractor
            : (req: Request) => req.params.orgId
        const minimumRequiredRole = args?.minimumRequiredRole

        return function(req: Request, res: Response, next: NextFunction) {

            // First we call into requireUser to validate the token and set the user
            return requireUser(req, res, async () => {
                try {
                    req.org = await verifyOrgMembership(req, res, debugMode, orgIdExtractorWithDefault, minimumRequiredRole)
                    next()
                } catch (e) {
                    if (e instanceof UnauthorizedException) {
                        handleUnauthorizedException({ exception: e, requireCredentials: true, debugMode, res, next })
                    } else if (e instanceof UnexpectedException) {
                        handleUnexpectedException({exception: e, debugMode, res})
                    } else if (e instanceof ForbiddenException) {
                        handleForbiddenExceptionWithRequiredCredentials(e, debugMode, res)
                    } else {
                        throw e
                    }
                }
            })
        }
    }
}

function extractBearerToken(req: Request): string {
    const authHeader = req.headers.authorization
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

async function verifyOrgMembership(req: Request,
                                   res: Response,
                                   debugMode: boolean,
                                   orgIdExtractorWithDefault: (req: Request) => string,
                                   minimumRequiredRole: string | undefined) {
    if (!req.user) {
        throw new UnauthorizedException("No user credentials found for requireOrgMember")
    }

    // Make sure the user is a member of the required org
    const requiredOrgId = orgIdExtractorWithDefault(req)
    const orgIdToOrgMemberInfo = req.user.orgIdToOrgMemberInfo
    if (!orgIdToOrgMemberInfo || !orgIdToOrgMemberInfo.hasOwnProperty(requiredOrgId)) {
        throw new ForbiddenException(`User is not a member of org ${requiredOrgId}`)
    }

    // If minimumRequiredRole is specified, make sure the user is at least that role
    const orgMemberInfo = orgIdToOrgMemberInfo[requiredOrgId]
    if (minimumRequiredRole !== undefined) {
        if (!req.roleNameToIndex) {
            throw new UnexpectedException("Configuration error: No roles found")
        }

        const validMinimumRequiredRole = req.roleNameToIndex.hasOwnProperty(minimumRequiredRole)
        if (!validMinimumRequiredRole) {
            throw new UnexpectedException(
                `Configuration error: Minimum required role (${minimumRequiredRole}) is invalid.`,
            )
        }

        const validSpecifiedRole = req.roleNameToIndex.hasOwnProperty(orgMemberInfo.userRoleName)
        if (!validSpecifiedRole) {
            throw new UnexpectedException(
                `Invalid user role (${minimumRequiredRole}). Try restarting the server to get the latest role config`,
            )
        }

        const minimumRequiredRoleIndex = req.roleNameToIndex[minimumRequiredRole]
        const userRoleIndex = req.roleNameToIndex[orgMemberInfo.userRoleName]
        // If the minimum required role is before the user role in the list, error out
        if (minimumRequiredRoleIndex < userRoleIndex) {
            throw new ForbiddenException(
                `User's role ${orgMemberInfo.userRoleName} doesn't meet minimum required role`,
            )
        }
    }

    return orgMemberInfo
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
    minimumRequiredRole?: string
    orgIdExtractor?: (req: Request) => string
}

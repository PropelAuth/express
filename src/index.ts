// For backwards compatibility
import {BaseAuthOptions, OrgMemberInfo, User} from "@propelauth/node"

export type {BaseAuthOptions, User, OrgMemberInfo}

export {initAuth, AuthOptions} from "./auth"
export type {RequireOrgMemberArgs} from "./auth"
export type {
    TokenVerificationMetadata,
    OrgQueryResponse,
    OrgQuery,
    UsersQuery,
    UsersInOrgQuery,
    UsersPagedResponse,
    CreateUserRequest,
    UpdateUserMetadataRequest,
    UpdateUserEmailRequest,
    CreateMagicLinkRequest,
    MagicLink,
    CreateAccessTokenRequest,
    AccessToken
} from "@propelauth/node"
export {
    AccessTokenCreationException,
    CreateUserException,
    ForbiddenException,
    MagicLinkCreationException,
    UserNotFoundException,
    UnauthorizedException,
    UnexpectedException,
    UpdateUserEmailException,
    UpdateUserMetadataException,
    Org,
    OrgIdToOrgMemberInfo,
    UserAndOrgMemberInfo,
    toOrgIdToOrgMemberInfo,
    UserMetadata,
} from "@propelauth/node"


declare global {
    namespace Express {
        interface Request {
            user?: User
            org?: OrgMemberInfo
        }
    }
}

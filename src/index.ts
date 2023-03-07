// For backwards compatibility
import {BaseAuthOptions, User, OrgMemberInfo} from "@propelauth/node"

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
} from "@propelauth/node"
export {
    CreateUserException,
    ForbiddenException,
    MagicLinkCreationException,
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

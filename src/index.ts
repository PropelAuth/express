// For backwards compatibility
import { BaseAuthOptions, OrgMemberInfo, User, UserClass } from "@propelauth/node"

export {
    AccessTokenCreationException,
    AddUserToOrgException,
    ApiKeyCreateException,
    ApiKeyDeleteException,
    ApiKeyFetchException,
    ApiKeyUpdateException,
    ApiKeyValidateException,
    ApiKeyValidateRateLimitedException,
    BadRequestException,
    ChangeUserRoleInOrgException,
    CreateOrgException,
    CreateUserException,
    ForbiddenException,
    MagicLinkCreationException,
    MigrateUserException,
    Org,
    OrgIdToOrgMemberInfo,
    RemoveUserFromOrgException,
    toOrgIdToOrgMemberInfo,
    toUser,
    UnauthorizedException,
    UnexpectedException,
    UpdateOrgException,
    UpdateUserEmailException,
    UpdateUserMetadataException,
    UpdateUserPasswordException,
    UserAndOrgMemberInfo,
    UserClass,
    UserMetadata,
    UserNotFoundException,
} from "@propelauth/node"
export type {
    AccessToken,
    AddUserToOrgRequest,
    ApiKeyFull,
    ApiKeyNew,
    ApiKeyResultPage,
    ApiKeysCreateRequest,
    ApiKeysQueryRequest,
    ApiKeyUpdateRequest,
    ApiKeyValidation,
    ChangeUserRoleInOrgRequest,
    CreateAccessTokenRequest,
    CreatedOrg,
    CreatedUser,
    CreateMagicLinkRequest,
    CreateOrgRequest,
    CreateUserRequest,
    CustomRoleMapping,
    CustomRoleMappings,
    InternalOrgMemberInfo,
    InternalUser,
    InviteUserToOrgRequest,
    LoginMethod,
    MagicLink,
    MigrateUserFromExternalSourceRequest,
    OrgApiKeyValidation,
    OrgQuery,
    OrgQueryResponse,
    PersonalApiKeyValidation,
    RemoveUserFromOrgRequest,
    SamlLoginProvider,
    SocialLoginProvider,
    TokenVerificationMetadata,
    UpdateOrgRequest,
    UpdateUserEmailRequest,
    UpdateUserMetadataRequest,
    UpdateUserPasswordRequest,
    UserProperties,
    UserInOrgMetadata,
    UsersInOrgPagedResponse,
    UserSignupQueryParams,
    UsersInOrgQuery,
    UsersPagedResponse,
    UsersQuery,
    RevokePendingOrgInviteRequest,
    FetchSamlSpMetadataResponse,
    SetSamlIdpMetadataRequest,
    IdpProvider,
} from "@propelauth/node"
export { AuthOptions, initAuth } from "./auth"
export type { RequireOrgMemberArgs } from "./auth"
export type { BaseAuthOptions, User, OrgMemberInfo }

declare global {
    namespace Express {
        interface Request {
            user?: User
            userClass?: UserClass
            org?: OrgMemberInfo
        }
    }
}

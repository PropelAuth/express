import { Org, OrgMemberInfo, User, UserMetadata } from "./user"

export { initAuth } from "./auth"
export type { AuthOptions, RequireOrgMemberArgs } from "./auth"
export type { Org, OrgMemberInfo, User, UserMetadata }
export type { OrgQueryResponse, OrgQuery, UsersQuery, UsersInOrgQuery, UsersPagedResponse, CreateUserRequest } from "./api"

declare global {
    namespace Express {
        interface Request {
            user?: User
            org?: OrgMemberInfo
        }
    }
}

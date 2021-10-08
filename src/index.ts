import { OrgMemberInfo, User, UserMetadata } from "./user"

export { initAuth } from "./auth"
export type { AuthOptions, RequireOrgMemberArgs } from "./auth"
export type { User, UserMetadata, OrgMemberInfo }

declare global {
    namespace Express {
        interface Request {
            user?: User
            org?: OrgMemberInfo
        }
    }
}

import {
    InternalOrgMemberInfo,
    InternalUser,
    OrgRoleStructure,
    TokenVerificationMetadata,
    toUser,
} from "@propelauth/node"
import { generateKeyPair } from "crypto"
import { Request, Response } from "express"
import jwt from "jsonwebtoken"
import nock from "nock"
import { v4 as uuid } from "uuid"
import { initAuth } from "../src"

const AUTH_URL = "https://auth.example.com"
const ALGO = "RS256"

afterEach(() => {
    jest.useRealTimers()
})

test("bad authUrl is rejected", async () => {
    expect(() => {
        initAuth({
            authUrl: "not.a.url",
            apiKey: "apiKey",
        })
    }).toThrow()
})

test("requireUser parses and sets req.user", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireUser } = initAuth({ authUrl: AUTH_URL + "/", apiKey })

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({ internalUser, privateKey })

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const res = null as any as Response
    const next = jest.fn()

    await requireUser(req, res, next)
    expect(req.user).toEqual(toUser(internalUser))
    expect(next).toBeCalledTimes(1)
    expect(nock.isDone()).toBe(true)
})

test("optionalUser parses and sets req.user", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { optionalUser } = initAuth({ authUrl: AUTH_URL, apiKey })

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({ internalUser, privateKey })

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const res = null as any as Response
    const next = jest.fn()

    await optionalUser(req, res, next)
    expect(req.user).toEqual(toUser(internalUser))
    expect(next).toBeCalledTimes(1)
    expect(nock.isDone()).toBe(true)
})

test("when manualTokenVerificationMetadata is specified, no fetch is made", async () => {
    // Never setup the token verification endpoint
    const { privateKey, publicKey } = await generateRsaKeyPair()
    const tokenVerificationMetadata: TokenVerificationMetadata = {
        issuer: AUTH_URL,
        verifierKey: publicKey,
    }
    const { requireUser } = initAuth({
        authUrl: AUTH_URL + "/",
        apiKey: "irrelevant api key for this test",
        manualTokenVerificationMetadata: tokenVerificationMetadata,
    })

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({ internalUser, privateKey })

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const res = null as any as Response
    const next = jest.fn()

    await requireUser(req, res, next)
    expect(req.user).toEqual(toUser(internalUser))
    expect(next).toBeCalledTimes(1)
    expect(nock.isDone()).toBe(true)
})

test("requireUser rejects expired access tokens", async () => {
    jest.useFakeTimers("modern")
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireUser } = initAuth({ authUrl: AUTH_URL + "/", apiKey })

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({ internalUser, expiresIn: "30m", privateKey })

    // 31 minutes
    jest.advanceTimersByTime(1000 * 60 * 31)

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const { res, sendFn } = createResExpectingStatusCode(401)
    const next = jest.fn()

    await requireUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
    expect(nock.isDone()).toBe(true)
})

test("optionalUser doesn't reject expired access token, but doesn't set req.user", async () => {
    jest.useFakeTimers("modern")
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { optionalUser } = initAuth({ authUrl: AUTH_URL, apiKey })

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({ internalUser, expiresIn: "30m", privateKey })

    // 31 minutes
    jest.advanceTimersByTime(1000 * 60 * 31)

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const res = null as any as Response
    const next = jest.fn()

    await optionalUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(next).toBeCalledTimes(1)
    expect(nock.isDone()).toBe(true)
})

test("requireUser rejects invalid access tokens", async () => {
    const { apiKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireUser } = initAuth({ authUrl: AUTH_URL, apiKey })

    const accessToken = "invalid"

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const { res, sendFn } = createResExpectingStatusCode(401)
    const next = jest.fn()

    await requireUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
    expect(nock.isDone()).toBe(true)
})

test("optionalUser doesn't reject invalid access tokens", async () => {
    const { apiKey } = await setupTokenVerificationMetadataEndpoint()
    const { optionalUser } = initAuth({ authUrl: AUTH_URL, apiKey })

    const accessToken = "invalid"

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const res = null as any as Response
    const next = jest.fn()

    await optionalUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(next).toBeCalledTimes(1)
    expect(nock.isDone()).toBe(true)
})

test("requireUser rejects missing authorization header", async () => {
    const { apiKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireUser } = initAuth({ authUrl: AUTH_URL, apiKey })

    const req = createReqWithAuthorizationHeader(undefined)
    const { res, sendFn } = createResExpectingStatusCode(401)
    const next = jest.fn()

    await requireUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
    expect(nock.isDone()).toBe(true)
})

test("optionalUser doesn't reject missing authorization header", async () => {
    const { apiKey } = await setupTokenVerificationMetadataEndpoint()
    const { optionalUser } = initAuth({ authUrl: AUTH_URL, apiKey })

    const req = createReqWithAuthorizationHeader(undefined)
    const res = null as any as Response
    const next = jest.fn()

    await optionalUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(next).toBeCalledTimes(1)
    expect(nock.isDone()).toBe(true)
})

test("requireUser fails with incorrect apiKey", async () => {
    const { apiKey } = await setupErrorTokenVerificationMetadataEndpoint(401)
    const { requireUser } = initAuth({ authUrl: AUTH_URL, apiKey: apiKey })

    const req = createReqWithAuthorizationHeader(`shouldnt matter`)
    const { res, sendFn } = createResExpectingStatusCode(503)
    const next = jest.fn()

    await requireUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
    expect(nock.isDone()).toBe(true)
})

test("optionalUser fails with incorrect apiKey", async () => {
    const { apiKey } = await setupErrorTokenVerificationMetadataEndpoint(401)
    const { optionalUser } = initAuth({ authUrl: AUTH_URL, apiKey: apiKey })

    const req = createReqWithAuthorizationHeader(`shouldnt matter`)
    const { res, sendFn } = createResExpectingStatusCode(503)
    const next = jest.fn()

    await optionalUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
    expect(nock.isDone()).toBe(true)
})

test("requireUser fails with incorrect issuer", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireUser } = initAuth({ authUrl: AUTH_URL, apiKey })

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({ internalUser, privateKey, issuer: "bad" })

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const { res, sendFn } = createResExpectingStatusCode(401)
    const next = jest.fn()

    await requireUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
    expect(nock.isDone()).toBe(true)
})

test("optionalUser doesn't fail with incorrect issuer, but no user set", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { optionalUser } = initAuth({ authUrl: AUTH_URL, apiKey })

    const internalUser = randomInternalUser()
    const accessToken = createAccessToken({ internalUser, privateKey, issuer: "bad" })

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const res = null as any as Response
    const next = jest.fn()

    await optionalUser(req, res, next)
    expect(req.user).toBeUndefined()
    expect(next).toHaveBeenCalled()
    expect(nock.isDone()).toBe(true)
})

test("requireOrgMember sets user and org for extracted org", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMember } = initAuth({ authUrl: AUTH_URL, apiKey })

    const orgMemberInfo = randomOrg()
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const accessToken = createAccessToken({ internalUser, privateKey })

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const res = null as any as Response
    const next = jest.fn()

    const orgIdExtractor = (_req: Request) => orgMemberInfo.org_id
    const requireOrgMemberMiddleware = requireOrgMember({ orgIdExtractor })
    await requireOrgMemberMiddleware(req, res, next)

    const user = toUser(internalUser)
    expect(req.user).toEqual(user)
    expect(req.org).toEqual(user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id])
    expect(next).toBeCalledTimes(1)
})

test("requireOrgMember fails for valid access token but unknown org", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMember } = initAuth({ authUrl: AUTH_URL, apiKey })

    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
    }
    const accessToken = createAccessToken({ internalUser, privateKey })

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const { res, sendFn } = createResExpectingStatusCode(403)
    const next = jest.fn()

    const orgIdExtractor = (_req: Request) => uuid()
    const requireOrgMemberMiddleware = requireOrgMember({ orgIdExtractor })
    await requireOrgMemberMiddleware(req, res, next)

    expect(req.org).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
})

test("requireOrgMember fails for invalid access token", async () => {
    const { apiKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMember } = initAuth({ authUrl: AUTH_URL, apiKey })

    const req = createReqWithAuthorizationHeader(undefined)
    const { res, sendFn } = createResExpectingStatusCode(401)
    const next = jest.fn()

    const orgIdExtractor = (_req: Request) => uuid()
    const requireOrgMemberMiddleware = requireOrgMember({ orgIdExtractor })
    await requireOrgMemberMiddleware(req, res, next)

    expect(req.user).toBeUndefined()
    expect(req.org).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
})

test("requireOrgMemberWithMinimumRequiredRole works with minimumRequiredRole", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMemberWithMinimumRole } = initAuth({ authUrl: AUTH_URL, apiKey })

    const { orgName, urlSafeOrgName } = randomOrgName()
    const orgMemberInfo: InternalOrgMemberInfo = {
        org_id: uuid(),
        org_name: orgName,
        org_metadata: {},
        url_safe_org_name: urlSafeOrgName,
        user_role: "Admin",
        user_permissions: [],
        inherited_user_roles_plus_current_role: ["Admin", "Member"],
        additional_roles: [],
        org_role_structure: OrgRoleStructure.SingleRole,
    }
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const user = toUser(internalUser)
    const accessToken = createAccessToken({ internalUser, privateKey })

    const rolesThatShouldSucceed = new Set(["Admin", "Member"])
    for (let role of ["Owner", "Admin", "Member"]) {
        const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
        const { res, sendFn } = createResExpectingStatusCode(403)
        const next = jest.fn()

        const orgIdExtractor = (_req: Request) => orgMemberInfo.org_id
        const requireOrgMemberMiddleware = requireOrgMemberWithMinimumRole({
            orgIdExtractor,
            minimumRequiredRole: role,
        })
        await requireOrgMemberMiddleware(req, res, next)

        if (rolesThatShouldSucceed.has(role)) {
            expect(req.user).toEqual(user)
            expect(req.org).toEqual(user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id])
            expect(next).toBeCalledTimes(1)
        } else {
            expect(req.org).toBeUndefined()
            expect(sendFn).toBeCalledTimes(1)
            expect(next).not.toHaveBeenCalled()
        }
    }
})

test("requireOrgMemberWithMinimumRole fails with invalid minimumRequiredRole", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMemberWithMinimumRole } = initAuth({ authUrl: AUTH_URL, apiKey })

    const { orgName, urlSafeOrgName } = randomOrgName()
    const orgMemberInfo: InternalOrgMemberInfo = {
        org_id: uuid(),
        org_name: orgName,
        org_metadata: {},
        url_safe_org_name: urlSafeOrgName,
        user_role: "Admin",
        user_permissions: [],
        inherited_user_roles_plus_current_role: ["Admin", "Member"],
        additional_roles: [],
        org_role_structure: OrgRoleStructure.SingleRole,
    }
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const accessToken = createAccessToken({ internalUser, privateKey })

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const { res, sendFn } = createResExpectingStatusCode(403)
    const next = jest.fn()

    const orgIdExtractor = (_req: Request) => orgMemberInfo.org_id
    const requireOrgMemberMiddleware = requireOrgMemberWithMinimumRole({
        orgIdExtractor,
        minimumRequiredRole: "js problems",
    })
    await requireOrgMemberMiddleware(req, res, next)

    expect(req.org).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
})

test("requireOrgMemberWithExactRole works with an exact role match", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMemberWithExactRole } = initAuth({ authUrl: AUTH_URL, apiKey })

    const { orgName, urlSafeOrgName } = randomOrgName()
    const orgMemberInfo: InternalOrgMemberInfo = {
        org_id: uuid(),
        org_name: orgName,
        org_metadata: {},
        url_safe_org_name: urlSafeOrgName,
        user_role: "Admin",
        user_permissions: [],
        inherited_user_roles_plus_current_role: ["Admin", "Member"],
        additional_roles: [],
        org_role_structure: OrgRoleStructure.SingleRole,
    }
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const user = toUser(internalUser)
    const accessToken = createAccessToken({ internalUser, privateKey })

    const rolesThatShouldSucceed = new Set(["Admin"])
    for (let role of ["Owner", "Admin", "Member", "other"]) {
        const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
        const { res, sendFn } = createResExpectingStatusCode(403)
        const next = jest.fn()

        const orgIdExtractor = (_req: Request) => orgMemberInfo.org_id
        const requireOrgMemberMiddleware = requireOrgMemberWithExactRole({ orgIdExtractor, role: role })
        await requireOrgMemberMiddleware(req, res, next)

        if (rolesThatShouldSucceed.has(role)) {
            expect(req.user).toEqual(user)
            expect(req.org).toEqual(user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id])
            expect(next).toBeCalledTimes(1)
        } else {
            expect(req.org).toBeUndefined()
            expect(sendFn).toBeCalledTimes(1)
            expect(next).not.toHaveBeenCalled()
        }
    }
})

test("requireOrgMemberWithPermission works with a permissions match", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMemberWithPermission } = initAuth({ authUrl: AUTH_URL, apiKey })

    const { orgName, urlSafeOrgName } = randomOrgName()
    const orgMemberInfo: InternalOrgMemberInfo = {
        org_id: uuid(),
        org_name: orgName,
        org_metadata: {},
        url_safe_org_name: urlSafeOrgName,
        user_role: "Admin",
        user_permissions: ["permA", "permB"],
        inherited_user_roles_plus_current_role: ["Admin", "Member"],
        additional_roles: [],
        org_role_structure: OrgRoleStructure.SingleRole,
    }
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const user = toUser(internalUser)
    const accessToken = createAccessToken({ internalUser, privateKey })

    const permissionsThatShouldSucceed = new Set(["permA", "permB"])
    for (let permission of ["permA", "permB", "permC", "permD"]) {
        const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
        const { res, sendFn } = createResExpectingStatusCode(403)
        const next = jest.fn()

        const orgIdExtractor = (_req: Request) => orgMemberInfo.org_id
        const requireOrgMemberMiddleware = requireOrgMemberWithPermission({ orgIdExtractor, permission: permission })
        await requireOrgMemberMiddleware(req, res, next)

        if (permissionsThatShouldSucceed.has(permission)) {
            expect(req.user).toEqual(user)
            expect(req.org).toEqual(user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id])
            expect(next).toBeCalledTimes(1)
        } else {
            expect(req.org).toBeUndefined()
            expect(sendFn).toBeCalledTimes(1)
            expect(next).not.toHaveBeenCalled()
        }
    }
})

test("requireOrgMemberWithAllPermissions works with a full permissions match", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMemberWithAllPermissions } = initAuth({ authUrl: AUTH_URL, apiKey })

    const { orgName, urlSafeOrgName } = randomOrgName()
    const orgMemberInfo: InternalOrgMemberInfo = {
        org_id: uuid(),
        org_name: orgName,
        org_metadata: {},
        url_safe_org_name: urlSafeOrgName,
        user_role: "Admin",
        user_permissions: ["permA", "permB"],
        inherited_user_roles_plus_current_role: ["Admin", "Member"],
        additional_roles: [],
        org_role_structure: OrgRoleStructure.SingleRole,
    }
    const internalUser: InternalUser = {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const user = toUser(internalUser)
    const accessToken = createAccessToken({ internalUser, privateKey })

    // Should succeed
    for (let permissions of [["permA", "permB"], ["permA"], ["permB"], []]) {
        const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
        const { res, sendFn } = createResExpectingStatusCode(403)
        const next = jest.fn()

        const orgIdExtractor = (_req: Request) => orgMemberInfo.org_id
        const requireOrgMemberMiddleware = requireOrgMemberWithAllPermissions({ orgIdExtractor, permissions })
        await requireOrgMemberMiddleware(req, res, next)

        expect(req.user).toEqual(user)
        expect(req.org).toEqual(user.orgIdToOrgMemberInfo && user.orgIdToOrgMemberInfo[orgMemberInfo.org_id])
        expect(next).toBeCalledTimes(1)
    }

    // Should fail
    for (let permissions of [["permA", "permB", "permC"], ["permC"], ["permB", "permC"]]) {
        const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
        const { res, sendFn } = createResExpectingStatusCode(403)
        const next = jest.fn()

        const orgIdExtractor = (_req: Request) => orgMemberInfo.org_id
        const requireOrgMemberMiddleware = requireOrgMemberWithAllPermissions({ orgIdExtractor, permissions })
        await requireOrgMemberMiddleware(req, res, next)

        expect(req.org).toBeUndefined()
        expect(sendFn).toBeCalledTimes(1)
        expect(next).not.toHaveBeenCalled()
    }
})

async function setupTokenVerificationMetadataEndpoint() {
    const { publicKey, privateKey } = await generateRsaKeyPair()
    const apiKey = randomString()

    const scope = nock(AUTH_URL)
        .get("/api/v1/token_verification_metadata")
        .matchHeader("authorization", `Bearer ${apiKey}`)
        .reply(
            200,
            JSON.stringify({
                verifier_key_pem: publicKey,
            })
        )

    return { privateKey, apiKey, scope }
}

async function setupErrorTokenVerificationMetadataEndpoint(statusCode: number) {
    const apiKey = randomString()

    const scope = nock(AUTH_URL)
        .get("/api/v1/token_verification_metadata")
        .matchHeader("authorization", `Bearer ${apiKey}`)
        .reply(statusCode)

    return { apiKey, scope }
}

function createReqWithAuthorizationHeader(authorizationHeader?: string): Request {
    return {
        headers: {
            authorization: authorizationHeader,
        },
    } as any as Request
}

function createResExpectingStatusCode(expectedStatusCode: number) {
    const sendFn = jest.fn()
    const res = {
        status: (statusCode: number) => {
            expect(statusCode).toEqual(expectedStatusCode)
            return {
                send: sendFn,
            }
        },
    } as any as Response
    return { res, sendFn }
}

function createAccessToken({ internalUser, privateKey, expiresIn, issuer }: CreateAccessTokenArgs): string {
    return jwt.sign(internalUser, privateKey, {
        algorithm: ALGO,
        expiresIn: expiresIn ? expiresIn : "1d",
        issuer: issuer ? issuer : AUTH_URL,
    })
}

async function generateRsaKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
    return new Promise((resolve, reject) => {
        generateKeyPair("rsa", { modulusLength: 2048 }, (err, publicKey, privateKey) => {
            if (err) {
                reject(err)
            } else {
                resolve({
                    publicKey: publicKey
                        .export({
                            type: "spki",
                            format: "pem",
                        })
                        .toString(),
                    privateKey: privateKey
                        .export({
                            type: "pkcs8",
                            format: "pem",
                        })
                        .toString(),
                })
            }
        })
    })
}

function randomString() {
    return (Math.random() + 1).toString(36).substring(3)
}

function randomOrgName() {
    const orgName = randomString()
    const urlSafeOrgName = orgName.replace(" ", "_").toLowerCase()
    return { orgName, urlSafeOrgName }
}

function randomInternalUser(): InternalUser {
    return {
        user_id: uuid(),
        email: uuid(),
        org_id_to_org_member_info: randomOrgIdToOrgMemberInfo(),
    }
}

function randomOrgIdToOrgMemberInfo(): { [org_id: string]: InternalOrgMemberInfo } | undefined {
    const numOrgs = Math.floor(Math.random() * 10)
    if (numOrgs === 0) {
        return undefined
    }

    const orgIdToOrgMemberInfo: { [org_id: string]: InternalOrgMemberInfo } = {}
    for (let i = 0; i < numOrgs; i++) {
        const org = randomOrg()
        orgIdToOrgMemberInfo[org.org_id] = org
    }
    return orgIdToOrgMemberInfo
}

function randomOrg(): InternalOrgMemberInfo {
    const { orgName, urlSafeOrgName } = randomOrgName()
    const role = choose(["Owner", "Admin", "Member"])
    return {
        org_id: uuid(),
        org_name: orgName,
        org_metadata: {},
        url_safe_org_name: urlSafeOrgName,
        user_role: role,
        inherited_user_roles_plus_current_role: [role],
        user_permissions: [],
        additional_roles: [],
        org_role_structure: OrgRoleStructure.SingleRole,
    }
}

function choose<T>(choices: T[]) {
    const index = Math.floor(Math.random() * choices.length)
    return choices[index]
}

interface CreateAccessTokenArgs {
    internalUser: InternalUser
    privateKey: string
    expiresIn?: string
    issuer?: string
}

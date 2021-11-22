import { generateKeyPair } from "crypto"
import { Request, Response } from "express"
import jwt from "jsonwebtoken"
import nock from "nock"
import { v4 as uuid } from "uuid"
import { initAuth, User } from "../src"
import { InternalOrgMemberInfo, InternalUser, toUser, UserRole } from "../src/user"
import { TokenVerificationMetadata } from "../src/api"

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
    const {privateKey, publicKey} = await generateRsaKeyPair()
    const tokenVerificationMetadata: TokenVerificationMetadata = {
        issuer: AUTH_URL,
        verifierKey: publicKey,
    };
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

test("toUser converts correctly with orgs", async () => {
    const internalUser: InternalUser = {
        user_id: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        org_id_to_org_member_info: {
            "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a": {
                org_id: "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a",
                org_name: "orgA",
                user_role: "Owner",
            },
            "4ca20d17-5021-4d62-8b3d-148214fa8d6d": {
                org_id: "4ca20d17-5021-4d62-8b3d-148214fa8d6d",
                org_name: "orgB",
                user_role: "Admin",
            },
            "15a31d0c-d284-4e7b-80a2-afb23f939cc3": {
                org_id: "15a31d0c-d284-4e7b-80a2-afb23f939cc3",
                org_name: "orgC",
                user_role: "Member",
            },
        },
    }
    const user: User = {
        userId: "cbf064e2-edaa-4d35-b413-a8d857329c12",
        orgIdToOrgMemberInfo: {
            "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a": {
                orgId: "99ee1329-e536-4aeb-8e2b-9f56c1b8fe8a",
                orgName: "orgA",
                userRole: UserRole.Owner,
            },
            "4ca20d17-5021-4d62-8b3d-148214fa8d6d": {
                orgId: "4ca20d17-5021-4d62-8b3d-148214fa8d6d",
                orgName: "orgB",
                userRole: UserRole.Admin,
            },
            "15a31d0c-d284-4e7b-80a2-afb23f939cc3": {
                orgId: "15a31d0c-d284-4e7b-80a2-afb23f939cc3",
                orgName: "orgC",
                userRole: UserRole.Member,
            },
        },
    }
    expect(toUser(internalUser)).toEqual(user)
})

test("toUser converts correctly without orgs", async () => {
    const internalUser: InternalUser = {
        user_id: "cbf064e2-edaa-4d35-b413-a8d857329c12",
    }
    const user: User = {
        userId: "cbf064e2-edaa-4d35-b413-a8d857329c12",
    }
    expect(toUser(internalUser)).toEqual(user)
})

test("requireOrgMember sets user and org for extracted org", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMember } = initAuth({ authUrl: AUTH_URL, apiKey })

    const orgMemberInfo = randomOrg()
    const internalUser: InternalUser = {
        user_id: uuid(),
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

test("requireOrgMember works with minimumRequiredRole", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMember } = initAuth({ authUrl: AUTH_URL, apiKey })

    const orgMemberInfo = {
        org_id: uuid(),
        org_name: randomString(),
        user_role: "Admin",
    }
    const internalUser: InternalUser = {
        user_id: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const user = toUser(internalUser)
    const accessToken = createAccessToken({ internalUser, privateKey })

    const rolesThatShouldSucceed = new Set([UserRole.Admin, UserRole.Member])
    for (let role of [UserRole.Owner, UserRole.Admin, UserRole.Member]) {
        const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
        const { res, sendFn } = createResExpectingStatusCode(403)
        const next = jest.fn()

        const orgIdExtractor = (_req: Request) => orgMemberInfo.org_id
        const requireOrgMemberMiddleware = requireOrgMember({ orgIdExtractor, minimumRequiredRole: role })
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

test("requireOrgMember fails with invalid minimumRequiredRole", async () => {
    const { apiKey, privateKey } = await setupTokenVerificationMetadataEndpoint()
    const { requireOrgMember } = initAuth({ authUrl: AUTH_URL, apiKey })

    const orgMemberInfo = {
        org_id: uuid(),
        org_name: randomString(),
        user_role: "Admin",
    }
    const internalUser: InternalUser = {
        user_id: uuid(),
        org_id_to_org_member_info: {
            [orgMemberInfo.org_id]: orgMemberInfo,
        },
    }
    const accessToken = createAccessToken({ internalUser, privateKey })

    const req = createReqWithAuthorizationHeader(`Bearer ${accessToken}`)
    const { res, sendFn } = createResExpectingStatusCode(503)
    const next = jest.fn()

    const orgIdExtractor = (_req: Request) => orgMemberInfo.org_id
    // @ts-ignore
    const requireOrgMemberMiddleware = requireOrgMember({ orgIdExtractor, minimumRequiredRole: "js problems" })
    await requireOrgMemberMiddleware(req, res, next)

    expect(req.org).toBeUndefined()
    expect(sendFn).toBeCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
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
                signing_algo: ALGO,
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
        header: jest.fn((x) => {
            expect(x).toEqual("authorization")
            return authorizationHeader
        }),
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
        generateKeyPair("rsa", { modulusLength: 1024 }, (err, publicKey, privateKey) => {
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

function randomInternalUser(): InternalUser {
    return {
        user_id: uuid(),
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
    return {
        org_id: uuid(),
        org_name: randomString(),
        user_role: choose(["Owner", "Admin", "Member"]),
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

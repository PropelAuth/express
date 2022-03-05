import qs from "querystring"
import { httpRequest } from "./http"
import { UserMetadata } from "./user"

export type TokenVerificationMetadata = {
    verifierKey: string
    issuer: string
    roleNameToIndex: {[role_name: string]: number}
}

type Role = {
    name: string
}

export function fetchTokenVerificationMetadata(authUrl: URL,
                                               apiKey: string,
                                               manualTokenVerificationMetadata?: TokenVerificationMetadata): Promise<TokenVerificationMetadata> {
    if (manualTokenVerificationMetadata) {
        return Promise.resolve(manualTokenVerificationMetadata)
    }

    return httpRequest(authUrl, apiKey, "/api/v1/token_verification_metadata", "GET").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw Error("apiKey is incorrect")
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw Error("Unknown error when fetching token verification metadata")
        }

        const jsonParse = JSON.parse(httpResponse.response)

        const role_name_to_index: {[role_name: string]: number} = {}
        jsonParse.roles?.forEach((role: Role, index: number) => {
            role_name_to_index[role.name] = index
        });

        return {
            verifierKey: jsonParse.verifier_key_pem,
            issuer: formatIssuer(authUrl),
            roleNameToIndex: role_name_to_index,
        }
    })
}

export function fetchUserMetadataByQuery(authUrl: URL, apiKey: string, query: any): Promise<UserMetadata | null> {
    const queryString = qs.stringify(query)
    return httpRequest(authUrl, apiKey, `/api/v1/user_info?${queryString}`, "GET").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw Error("apiKey is incorrect")
        } else if (httpResponse.statusCode === 404) {
            return null
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw Error("Unknown error when fetching user metadata")
        }

        const jsonParse = JSON.parse(httpResponse.response)
        return {
            userId: jsonParse.user_id,
            email: jsonParse.email,
            emailConfirmed: jsonParse.email_confirmed,

            username: jsonParse.username,
            firstName: jsonParse.first_name,
            lastName: jsonParse.last_name,
            pictureUrl: jsonParse.picture_url,

            locked: jsonParse.locked,
            enabled: jsonParse.enabled,
            mfaEnabled: jsonParse.mfa_enabled,

        }
    })
}

export function fetchBatchUserMetadata(
    authUrl: URL,
    apiKey: string,
    type: string,
    values: string[],
): Promise<{ [key: string]: UserMetadata }> {
    return httpRequest(authUrl, apiKey, `/api/v1/user_info/${type}`, "POST", JSON.stringify(values)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw Error("apiKey is incorrect")
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw Error("Unknown error when fetching batch user metadata")
            }

            // Make user_id to userId since the API response is snake_case and typescript convention is camelCase
            return JSON.parse(httpResponse.response, function(key, value) {
                if (key === "user_id") {
                    this.userId = value
                } else if (key === "email_confirmed") {
                    this.emailConfirmed = value;
                } else if (key === "first_name") {
                    this.firstName = value;
                } else if (key === "last_name") {
                    this.lastName = value;
                } else if (key === "picture_url") {
                    this.pictureUrl = value;
                } else if (key === "mfa_enabled") {
                    this.mfaEnabled = value;
                } else {
                    return value
                }
            })
        },
    )
}

function formatIssuer(authUrl: URL): string {
    return authUrl.origin
}
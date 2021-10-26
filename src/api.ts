import { Algorithm } from "jsonwebtoken"
import qs from "querystring"
import { httpRequest } from "./http"
import { UserMetadata } from "./user"

export type TokenVerificationMetadata = {
    verifierKey: string
    issuer: string
}

export function fetchTokenVerificationMetadata(authUrl: URL, apiKey: string): Promise<TokenVerificationMetadata> {
    return httpRequest(authUrl, apiKey, "/api/v1/token_verification_metadata", "GET").then((httpResponse) => {
        if (httpResponse.statusCode === 401) {
            throw Error("apiKey is incorrect")
        } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
            throw Error("Unknown error when fetching token verification metadata")
        }

        const jsonParse = JSON.parse(httpResponse.response)
        return {
            verifierKey: jsonParse.verifier_key_pem,
            issuer: formatIssuer(authUrl),
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
            username: jsonParse.username,
        }
    })
}

export function fetchBatchUserMetadata(
    authUrl: URL,
    apiKey: string,
    type: string,
    values: string[]
): Promise<{ [key: string]: UserMetadata }> {
    return httpRequest(authUrl, apiKey, `/api/v1/user_info/${type}`, "POST", JSON.stringify(values)).then(
        (httpResponse) => {
            if (httpResponse.statusCode === 401) {
                throw Error("apiKey is incorrect")
            } else if (httpResponse.statusCode && httpResponse.statusCode >= 400) {
                throw Error("Unknown error when fetching batch user metadata")
            }

            // Make user_id to userId since the API response is snake_case and typescript convention is camelCase
            return JSON.parse(httpResponse.response, function (key, value) {
                if (key === "user_id") {
                    this.userId = value
                } else {
                    return value
                }
            })
        }
    )
}

function formatIssuer(authUrl: URL): string {
    return authUrl.origin
}

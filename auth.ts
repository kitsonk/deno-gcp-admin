import { importPKCS8, SignJWT } from "https://deno.land/x/jose@v4.8.1/index.ts";

const ALG = "RS256";
const AUD =
  "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

export interface ServiceAccountJSON {
  client_email: string;
  private_key: string;
  private_key_id: string;
}

/** Generates a custom token (JWT) that allows a service account to authenticate
 * against Google APIs. */
export async function createCustomToken(
  json: ServiceAccountJSON,
  claims?: Record<string, unknown>,
): Promise<string> {
  const key = await importPKCS8(json.private_key, ALG);
  return new SignJWT({
    uid: json.private_key_id,
    claims,
  })
    .setProtectedHeader({ alg: ALG })
    .setIssuer(json.client_email)
    .setSubject(json.client_email)
    .setAudience(AUD)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(key);
}

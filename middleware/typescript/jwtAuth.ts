/**
 * Middleware reutilizable de validación JWT para Node.js / TypeScript (BT-03).
 *
 * Diseñado para M2 (TS), M4 (Ticket Engine) y M6 (Validator Backend).
 * Cumple RNF-02, RNF-03 y Sección 4.5:
 * - Usa librería `jose` con `createRemoteJWKSet` y caché de 10 minutos (600,000 ms).
 * - Acepta exclusivamente algoritmo `ES256` (rechaza `none`, `HS256`, etc.).
 * - Valida `iss`, `aud`, `exp`, `nbf` y la presencia de `sub`, `role` e `idh`.
 */

import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify, type JWTPayload } from 'jose';

export interface AuthenticatedUser {
  sub: string;
  role: 'buyer' | 'admin' | 'staff' | 'organizer';
  idh: string;
  jti: string;
  iss: string;
  aud: string | string[];
}

export interface JwtVerifierConfig {
  jwksUrl?: string;
  issuer?: string;
  audience?: string;
  cacheMaxAgeMs?: number;
}

export function createJwtVerifier(config: JwtVerifierConfig = {}) {
  const jwksUrl = config.jwksUrl ?? process.env.M1_JWKS_URL ?? 'http://m1-auth:8000/.well-known/jwks.json';
  const issuer = config.issuer ?? process.env.JWT_ISSUER ?? 'https://auth.boletera.local';
  const audience = config.audience ?? process.env.JWT_AUDIENCE ?? 'boletera-api';
  const cacheMaxAge = config.cacheMaxAgeMs ?? 10 * 60 * 1000; // 10 minutos

  const JWKS = createRemoteJWKSet(new URL(jwksUrl), {
    cacheMaxAge,
    cooldownDuration: 30_000,
    timeoutDuration: 5_000,
  });

  async function verifyToken(token: string): Promise<AuthenticatedUser> {
    const protectedHeader = decodeProtectedHeader(token);

    if (protectedHeader.alg !== 'ES256') {
      throw new Error('Algoritmo JWT no permitido; solo se acepta ES256.');
    }
    if (!protectedHeader.kid) {
      throw new Error('Falta kid en el header del JWT.');
    }

    const { payload } = await jwtVerify(token, JWKS, {
      algorithms: ['ES256'],
      issuer,
      audience,
      requiredClaims: ['sub', 'role', 'iss', 'aud', 'exp', 'iat', 'jti', 'idh'],
    });

    return extractUser(payload);
  }

  return { verifyToken };
}

function extractUser(payload: JWTPayload): AuthenticatedUser {
  if (
    typeof payload.sub !== 'string' ||
    typeof payload.role !== 'string' ||
    typeof payload.idh !== 'string' ||
    typeof payload.jti !== 'string' ||
    typeof payload.iss !== 'string' ||
    !payload.aud
  ) {
    throw new Error('Claims obligatorios faltantes en el JWT.');
  }

  return {
    sub: payload.sub,
    role: payload.role as AuthenticatedUser['role'],
    idh: payload.idh,
    jti: payload.jti,
    iss: payload.iss,
    aud: payload.aud,
  };
}

/**
 * Middleware estilo Express / Connect para proteger rutas REST.
 */
export function expressJwtMiddleware(config: JwtVerifierConfig = {}) {
  const { verifyToken } = createJwtVerifier(config);

  return async function jwtAuthMiddleware(req: any, res: any, next: any) {
    try {
      const authHeader: string | undefined = req.headers?.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          type: 'https://auth.boletera.local/errors/unauthorized',
          title: 'Unauthorized',
          status: 401,
          detail: 'Se requiere token Bearer.',
        });
      }

      const token = authHeader.slice('Bearer '.length).trim();
      req.user = await verifyToken(token);
      return next();
    } catch (err: any) {
      return res.status(401).json({
        type: 'https://auth.boletera.local/errors/invalid-token',
        title: 'Unauthorized',
        status: 401,
        detail: err?.message ?? 'Token inválido o expirado.',
      });
    }
  };
}

export function requireRoles(...allowedRoles: AuthenticatedUser['role'][]) {
  return function roleGuard(req: any, res: any, next: any) {
    const role = req.user?.role;
    if (!role || !allowedRoles.includes(role)) {
      return res.status(403).json({
        type: 'https://auth.boletera.local/errors/forbidden',
        title: 'Forbidden',
        status: 403,
        detail: 'No tienes permisos suficientes para esta operación.',
      });
    }
    return next();
  };
}

# ADR-0009: Tercera entidad de confianza (TTP) fuera de M1: raíz de la CA y sellado de tiempo RFC 3161
Estado: Propuesto (2026-11-18) · Pendiente de confirmar alcance con la profesora (DF-02)
Autor: Diego Flores Madrigal (Tech Lead M1)

## Contexto
La profesora pidió una TTP sin precisar su función. Si M1 fuera dueño de la raíz sería juez y parte.

## Decisión (opción A + B de la planeación 6.3)
- `trust-authority`, operada por el grupo de integración (dos custodios de equipos distintos a M1).
- A: custodia la llave raíz P-256 offline (PKCS#8 cifrado) y firma las 3 intermedias de M1 en la ceremonia.
- B: expone `POST /trust/timestamp` (RFC 3161, SHA-256); M1 sella cada CRL y revocaciones/cambios de rol.
- M1 implementa el cliente (`app/crypto/tsa_client.py`, variable `TSA_URL`) y la carga de intermedias
  (`scripts/ceremony/ceremony.py`). Mientras no exista la TTP, `PKI_DEV_BOOTSTRAP=true` simula la raíz en desarrollo.

## Consecuencias
+ Un compromiso de M1 se corrige revocando sus intermedias desde la raíz.
+ Prueba de tiempo independiente para CRL, boletos (M4) y bitácora de ingresos (M6).
- Un servicio más que construir; si M1 lo debe construir, se activa la contingencia del roadmap (JO-08).

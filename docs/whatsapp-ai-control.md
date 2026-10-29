# WhatsApp AI Control Center

Módulo dentro del administrador existente de Ferumi Shop (`/admin/whatsapp`). No reemplaza la tienda, el despacho ni la caja.

## Qué corrige

Los enlaces de PagoPar se repetían porque cada confirmación creaba un pedido nuevo con `idempotencyKey` basado en la hora, y el texto del modelo volvía a incluir el mismo enlace que ya había armado la herramienta. Los webhooks repetidos solo se frenaban en memoria de un proceso.

Ahora cada operación de pago tiene una clave estable. Si PagoPar no confirma el resultado, la operación queda incierta y no se llama de nuevo. Un mensaje de WhatsApp con el mismo `wamid` se registra una sola vez.

## Variables nuevas

No hace falta ninguna variable para el funcionamiento actual. Opcionales:

- `WA_VISION_ENABLED=true` junto con `GEMINI_API_KEY` y `WA_VISION_MODEL` para analizar fotos de productos. Sin eso, la búsqueda visual queda apagada y el panel lo dice.
- `WA_PAYMENT_LINK_RESEND_COOLDOWN_MS` (por defecto 120000) espera mínima para reenviar un enlace ya enviado.

No pongas secretos en el código ni en el panel.

## Datos

Se agregan colecciones `wa_*` y campos opcionales en pedidos, productos y usuarios admin. No se borran pedidos, clientes ni productos.

## Reversión

1. Volvé el deploy al commit anterior.
2. Las colecciones nuevas pueden quedar sin uso.
3. Si algún pedido quedó con `shippingMethod = delivery_propio` o `paymentMethod = transferencia`, cambialo a un valor anterior (`retiro` o `pagopar`) antes de volver, porque el código viejo no acepta esos valores.

## Pendiente que depende de credenciales

WhatsApp, PagoPar, DeepInfra, Cloudinary y la visión no se pueden probar desde este entorno sin las claves reales. El panel muestra si cada una está configurada, sin revelar los secretos.

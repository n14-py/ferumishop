# WhatsApp AI Control Center

Módulo dentro del administrador existente de Ferumi Shop (`/admin/whatsapp`). No reemplaza la tienda, el despacho ni la caja.

## Qué corrige

Los enlaces de PagoPar se repetían porque cada confirmación creaba un pedido nuevo con `idempotencyKey` basado en la hora, y el texto del modelo volvía a incluir el mismo enlace que ya había armado la herramienta. Los webhooks repetidos solo se frenaban en memoria de un proceso.

Ahora cada operación de pago tiene una clave estable. Si PagoPar no confirma el resultado, la operación queda incierta y no se llama de nuevo. Un mensaje de WhatsApp con el mismo `wamid` se registra una sola vez.

## Transferencia y envío

En WhatsApp AI → Pagos se cargan banco, alias y nombre. La IA envía exactamente esos datos y el comprobante queda en ese mismo apartado, sin marcar el pago como confirmado.

En Tarifas, un lugar como «Capiatá ruta 2» con un precio aplica a todo destino que contenga esa frase. Si también existe «Capiatá», gana la frase más específica.

Una pregunta como «¿el delivery propio sale a las 6?» se responde con el horario de las 18:00. No dispara una búsqueda de productos ni manda fotos. La ubicación se guarda en la conversación y al cliente solo se le dice el costo del envío que ya eligió, o si está en zona o va por transportadora.

Los pasos siguen en el mismo orden: saludo y nombre si quiere pedir, el producto, el envío, el pago y recién ahí los datos. Esos pasos no se pegan como formulario. El modelo los dice en un mensaje, contestando la consulta. Si la IA no responde, queda el texto del paso para no perder el dato (precio, alias o enlace).

El botón Confirmar de Comprobantes manda la acción en un campo oculto. Al confirmar, el comprobante queda confirmado, el cliente recibe el aviso y la conversación recuerda que el pago ya está confirmado. La foto se transcribe completa y de ese texto salen emisor, destinatario, monto y banco.

PagoPar no tiene monto mínimo. El enlace incluye QR, tarjeta de crédito y débito. Si el envío tiene precio, ese importe entra en el total que se manda a PagoPar.

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

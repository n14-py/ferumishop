# WhatsApp AI Control Center

Módulo dentro del administrador existente de Ferumi Shop (`/admin/whatsapp`). No reemplaza la tienda, el despacho ni la caja.

## Qué corrige

Los enlaces de PagoPar se repetían porque cada confirmación creaba un pedido nuevo con `idempotencyKey` basado en la hora, y el texto del modelo volvía a incluir el mismo enlace que ya había armado la herramienta. Los webhooks repetidos solo se frenaban en memoria de un proceso.

Ahora cada operación de pago tiene una clave estable. Si PagoPar no confirma el resultado, la operación queda incierta y no se llama de nuevo. Un mensaje de WhatsApp con el mismo `wamid` se registra una sola vez.

## Transferencia y envío

En WhatsApp AI → Pagos se cargan banco, alias y nombre. La IA envía exactamente esos datos y el comprobante queda en ese mismo apartado, sin marcar el pago como confirmado.

En Tarifas, un lugar como «Capiatá ruta 2» con un precio aplica a todo destino que contenga esa frase. Si también existe «Capiatá», gana la frase más específica.

Una pregunta como «¿el delivery propio sale a las 6?» se responde con el horario de las 18:00. No dispara una búsqueda de productos ni manda fotos. La ubicación se guarda en la conversación y al cliente solo se le dice el costo del envío que ya eligió, o si está en zona o va por transportadora.

Los pasos siguen en el mismo orden: saludo y nombre, la consulta y el producto, el envío en tres bloques (delivery propio a las 18:00, Motobolt y transportadora), el pago y recién ahí los datos. El alias y el total se pasan cuando elige transferencia. PagoPar pide solo nombre, cédula, correo y teléfono. La foto del comprobante se transcribe y, si parece una transferencia, queda parcial hasta que una persona la apruebe.

Si en unos segundos llegan juntos el comprobante y la ubicación, se leen los dos antes de contestar. La espera es de 10 segundos (`WA_REPLY_DELAY_MS`). El ticket térmico imprime nombre, teléfono y ciudad. El QR del ticket, en el admin, marca preparado; si lo abre otra persona, ve la ubicación, el WhatsApp y si hay que cobrar.

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

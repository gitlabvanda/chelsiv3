# اتصال پنل به Claude Desktop (MCP)

## ۱) روی Railway
در Variables سرویس پنل این متغیر را اضافه کنید (حداقل ۱۶ کاراکتر، تصادفی):

    MCP_TOKEN=<یک رشته‌ی طولانی و تصادفی>

برای ساخت: `openssl rand -hex 24`
بعد از ذخیره، سرویس خودکار redeploy می‌شود. بدون این متغیر، قابلیت MCP کلاً غیرفعال است.

آدرس MCP:  https://<دامنه-پنل>/<ADMIN_PATH>/mcp

## ۲) روش A — Custom Connector (پیشنهادی، ساده‌تر)
Claude Desktop → Settings → Connectors → Add custom connector
آدرس را با توکن داخل مسیر بدهید:

    https://<دامنه-پنل>/<ADMIN_PATH>/mcp/<MCP_TOKEN>

## ۳) روش B — فایل claude_desktop_config.json (توکن در هدر، امن‌تر)
نیاز به Node.js دارد:

    {
      "mcpServers": {
        "panel": {
          "command": "npx",
          "args": ["-y", "mcp-remote",
                   "https://<دامنه-پنل>/<ADMIN_PATH>/mcp",
                   "--header", "Authorization:${AUTH}"],
          "env": { "AUTH": "Bearer <MCP_TOKEN>" }
        }
      }
    }

بعد از ذخیره، Claude Desktop را کامل ببندید و دوباره باز کنید.

## ابزارهای موجود (۱۷ عدد)
panel_stats, list_endpoints, create_endpoint, edit_endpoint, rotate_endpoint, delete_endpoint,
list_accounts, create_account, edit_account, set_speed_limit, toggle_account, reset_account_usage,
renew_account, delete_account, get_settings, update_settings, diagnose

## امنیت
- توکن را جایی منتشر نکنید؛ هر کس آن را داشته باشد کنترل کامل پنل را دارد.
- در روش A توکن در URL است و ممکن است در لاگ‌ها دیده شود؛ برای حساس‌ترین حالت روش B را بزنید.
- برای ابطال: مقدار MCP_TOKEN را عوض کنید یا حذفش کنید.

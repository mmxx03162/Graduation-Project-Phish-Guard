from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        """
        Optional: auto-update OpenPhish blacklist on server startup.

        - Runs in a background thread to avoid blocking startup.
        - In Django dev server, this runs only in the reloader child process (RUN_MAIN="true"),
          to avoid double execution.
        - In production (no autoreloader), it runs once per process/worker.
        """
        import os

        try:
            from django.conf import settings

            if not getattr(settings, "OPENPHISH_AUTO_UPDATE_ON_STARTUP", False):
                return

            # In dev server with autoreload enabled, Django spawns two processes:
            # a parent watcher (RUN_MAIN is unset) and a child server (RUN_MAIN="true").
            # We only want the child to run the startup updater.
            if getattr(settings, "DEBUG", False) and os.environ.get("RUN_MAIN") != "true":
                return

            limit = int(getattr(settings, "OPENPHISH_STARTUP_LIMIT", 300))
            replace = bool(getattr(settings, "OPENPHISH_STARTUP_REPLACE", True))
        except Exception:
            return

        def _runner():
            try:
                from django.core.management import call_command

                args = ["--limit", str(limit)]
                if not replace:
                    args.append("--no-replace")
                call_command("update_openphish_blacklist", *args)
            except Exception:
                # Never crash startup due to feed update failures.
                return

        try:
            import threading

            t = threading.Thread(target=_runner, daemon=True, name="openphish-startup-update")
            t.start()
        except Exception:
            return

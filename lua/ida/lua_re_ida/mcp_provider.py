"""MCP provider factory discovered from installed entry-point metadata. AGPL-3.0."""


def create_provider(provider_type):
    # Use the host's type so GUI and idalib never import each other's MCP package.
    from .pseudocode import decompile, references, capabilities

    def supports():
        import ida_ida
        return ida_ida.inf_get_procname() == 'luare'

    def ready():
        status = capabilities()
        if not status['decompiler_ready']:
            raise RuntimeError(status['decompiler_hint'])
        return True

    return provider_type(
        name='Lua RE / unluac', language='Lua', supports=supports,
        decompile=lambda ea, include_addresses: decompile(ea).render(include_addresses),
        references=references, ready=ready,
    )

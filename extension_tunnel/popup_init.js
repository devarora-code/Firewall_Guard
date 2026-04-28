// Popup initialization script
try {
    import('./sandbox.js').then(() => {
        console.log('[Popup] Sandbox module loaded successfully');
    }).catch(() => {
        console.log('[Popup] Sandbox module not available - running in basic mode');
        window.SandboxEnvironment = undefined;
    });
} catch (error) {
    console.log('[Popup] Sandbox loading failed - running in basic mode');
    window.SandboxEnvironment = undefined;
}

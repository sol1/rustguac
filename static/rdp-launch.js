async function launchRdp(target, password) {
    const query = new URLSearchParams();
    if (target) query.set('connectTo', target);
    const headers = { 'X-Rustguac-Launch': '1' };
    const request = { method: 'POST', headers };
    if (password !== undefined) {
        headers['Content-Type'] = 'application/json';
        request.body = JSON.stringify({ password });
    }
    const response = await fetch('/rdp/launch?' + query.toString(), request);
    const result = await response.text();
    if (!response.ok) throw new Error(result);
    if (!result.startsWith('/client/')) throw new Error('Could not open the Remote Desktop session.');
    return result;
}

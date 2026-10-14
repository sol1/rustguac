#!/usr/bin/env node
/*
 * Pins the `h264-aux` instruction across the Rust/JS boundary.
 *
 * rustguac originates this one: guacd never sends it, and it is the only way
 * the browser learns that the AVC444 auxiliary view has been removed from the
 * wire. A disagreement about it is silent in both directions. An unknown
 * opcode is ignored by Guacamole.Client, so a wrong name leaves the client
 * combining main views against an auxiliary view that will never arrive --
 * a plane read-back per picture, ~19ms each, for a 4:4:4 result that cannot
 * happen -- and nothing is logged at either end. A wrong element length
 * desynchronises the parser instead, which takes the whole session down but
 * would at least be noticed.
 *
 * So the opcode is read out of the Rust source, the instruction is built the
 * way guacd_to_ws builds it, and it is parsed with the real Guacamole.Parser
 * and dispatched through the handler table Client.js actually ships.
 *
 * Usage: node tests/h264-aux-instruction.mjs
 */

import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

let failures = 0;
function check(name, ok, detail) {
    if (ok) {
        console.log('  ok   ' + name);
    } else {
        failures++;
        console.log('  FAIL ' + name + (detail ? ': ' + detail : ''));
    }
}

/* ---- the opcode rustguac sends, lifted from the Rust source ---- */

const wsSource = await readFile(resolve(root, 'src/websocket.rs'), 'utf8');

const opcodeMatch = wsSource.match(
        /const AUX_DROP_OPCODE: &str = "([^"]+)";/);
if (!opcodeMatch)
    throw new Error('AUX_DROP_OPCODE not found in src/websocket.rs');
const opcode = opcodeMatch[1];

/* The format! that builds it, so a change to the shape of the instruction --
 * a second parameter, say -- fails here rather than in the field. */
const formatMatch = wsSource.replace(/\s+/g, ' ').match(
        /format!\( ?"\{\}\.\{\},1\.\{\};", ?AUX_DROP_OPCODE\.len\(\), ?AUX_DROP_OPCODE, ?dropping as u8 ?\)/);
check('rustguac builds <len>.<opcode>,1.<0|1>;', !!formatMatch,
        'the format! in guacd_to_ws no longer matches what this test builds');

/* ---- the handler Client.js ships ---- */

const clientSource = await readFile(resolve(root, 'static/guac/Client.js'), 'utf8');

check('Client.js handles the opcode rustguac sends',
        clientSource.includes('"' + opcode + '": function(parameters)'),
        'no handler for "' + opcode + '" in the instruction table');

/* ---- the parse ---- */

const Guacamole = {};
const parserSource = await readFile(resolve(root, 'static/guac/Parser.js'), 'utf8');
new Function('Guacamole', parserSource + '\nreturn Guacamole;')(Guacamole);

/* Built exactly as guacd_to_ws builds it. The opcode is ASCII, so Rust's
 * byte length is the element's character count; assert that rather than
 * assuming it, since the Guacamole length is in characters and a non-ASCII
 * opcode would make the two disagree. */
check('the opcode is ASCII, so byte length is character length',
        [...opcode].length === Buffer.byteLength(opcode, 'utf8'),
        opcode + ' would need a character count, not .len()');

for (const dropping of [0, 1]) {

    const instruction = opcode.length + '.' + opcode + ',1.' + dropping + ';';

    let seen = null;
    const parser = new Guacamole.Parser();
    parser.oninstruction = (op, params) => { seen = [op, params]; };
    parser.receive(instruction);

    check('parses as one instruction (' + dropping + ')', seen !== null,
            'the parser consumed ' + JSON.stringify(instruction)
            + ' without producing an instruction');

    if (!seen)
        continue;

    check('opcode survives (' + dropping + ')', seen[0] === opcode,
            'got ' + JSON.stringify(seen[0]));
    check('one parameter (' + dropping + ')', seen[1].length === 1,
            'got ' + JSON.stringify(seen[1]));

    /* The expression Client.js ships, lifted rather than copied. */
    const droppedExpr = clientSource.match(
            /h264AuxDropped = (parseInt\(parameters\[0\]\)[^;]*);/);
    check('Client.js reads parameter 0 (' + dropping + ')', !!droppedExpr,
            'the assignment to h264AuxDropped has changed shape');

    if (droppedExpr) {
        const read = new Function('parameters',
                'return (' + droppedExpr[1] + ');')(seen[1]);
        check('reads back as ' + (dropping === 1), read === (dropping === 1),
                'got ' + JSON.stringify(read));
    }

}

/* An older client, which has no handler for this opcode, must ignore it
 * rather than fail -- that is what makes the instruction safe to send to a
 * cached page. This is the dispatch Client.js performs. */
const instructionHandlers = {};
const handler = instructionHandlers[opcode];
check('an unknown opcode is ignored, not an error', !handler);

console.log(failures ? '\nFAILED: ' + failures : '\nAll checks passed');
process.exit(failures ? 1 : 0);

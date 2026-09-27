import { encodeName, decodeName, MAX_NAME_LENGTH, MAX_LABEL_LENGTH } from './core.js';

/**
 * Public surface for dns-name-wire.
 *
 * Only re-exports; all logic lives in ./core.js so that the test
 * suite and consumers share a single implementation module.
 */
export { encodeName, decodeName, MAX_NAME_LENGTH, MAX_LABEL_LENGTH };

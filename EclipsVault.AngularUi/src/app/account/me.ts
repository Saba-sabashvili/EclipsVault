import type { paths } from '../ui-api/schema.generated';

/** The generated success response of `GET /api/ui/me`: the signed-in vault account. */
export type Me = paths['/api/ui/me']['get']['responses'][200]['content']['application/json'];

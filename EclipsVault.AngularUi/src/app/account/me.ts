/** The response of `GET /api/ui/me`: the signed-in vault account. */
export interface Me {
  username: string;
  displayName: string;
  clearance: string;
  project: string;
}

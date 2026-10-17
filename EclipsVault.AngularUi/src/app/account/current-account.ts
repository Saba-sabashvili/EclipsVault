import { httpResource } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Me } from './me';

/** One live session snapshot shared by the shell and the page. Refresh replaces both together. */
@Injectable({ providedIn: 'root' })
export class CurrentAccount {
  readonly me = httpResource<Me>(() => '/api/ui/me');
}

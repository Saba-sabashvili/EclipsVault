import { httpResource } from '@angular/common/http';
import { Component } from '@angular/core';
import { Me } from './me';

@Component({
  selector: 'app-account-page',
  templateUrl: './account-page.html',
})
export class AccountPage {
  protected readonly me = httpResource<Me>(() => '/api/ui/me');
}

import { Component, inject } from '@angular/core';
import { CurrentAccount } from './current-account';

@Component({
  selector: 'app-account-page',
  templateUrl: './account-page.html',
})
export class AccountPage {
  protected readonly me = inject(CurrentAccount).me;
}

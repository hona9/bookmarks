import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  signup() {
    return 'signup';
  }

  login() {
    return 'login';
  }
}

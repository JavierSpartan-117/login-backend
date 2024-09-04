import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { ValidateUserDto } from './dto/validate-user.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('create-user')
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.createUser(createUserDto);
  }

  @Post('login')
  validateUser(@Body() validateUserDto: ValidateUserDto) {
    return this.authService.validateUser(validateUserDto);
  }

  @Post('verify-mfa')
  verifyMfa(@Body() { email, mfaToken }: { email: string; mfaToken: string }) {
    return this.authService.validateMfaToken(email, mfaToken);
  }
}

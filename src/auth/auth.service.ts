import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { ValidateUserDto } from './dto/validate-user.dto';
import * as SibApiV3Sdk from 'sib-api-v3-sdk';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async createUser(createUserDto: CreateUserDto) {
    try {
      const { password, ...userData } = createUserDto;
      const user = this.userRepository.create({
        ...userData,
        password: bcrypt.hashSync(password, 10),
      });
      await this.userRepository.save(user);
      await this.generateMfaToken(user);
      return user;
    } catch (error) {
      this.handleDBError(error, createUserDto.email);
    }
  }

  async validateUser(validateUserDto: ValidateUserDto) {
    const { email, password } = validateUserDto;

    const user = await this.userRepository.findOne({
      where: { email },
      select: { id: true, email: true, password: true, isActive: true },
    });
    if (!user) {
      throw new BadRequestException(
        `No hay ningun usuario con el email ${email} registrado`,
      );
    }
    if (!bcrypt.compareSync(password, user.password)) {
      throw new BadRequestException('Contraseña incorrecta');
    }
    if (!user.isActive) {
      throw new BadRequestException('Usuario inactivo');
    }

    return await this.generateMfaToken(user);
    // return user;
  }

  private async generateMfaToken(user: User) {
    const mfaToken = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code
    const mfaTokenExpiresAt = new Date();
    mfaTokenExpiresAt.setMinutes(mfaTokenExpiresAt.getMinutes() + 5); // 5 minutes

    await this.userRepository.update(user.id, {
      mfaToken,
      mfaTokenExpiresAt,
    });
    // user.mfaToken = mfaToken;
    // user.mfaTokenExpiresAt = mfaTokenExpiresAt;
    // await this.userRepository.save(user);

    return await this.sendMfaToken(user.email, mfaToken);
  }

  private async sendMfaToken(email: string, mfaToken: string) {
    const defaultClient = SibApiV3Sdk.ApiClient.instance;
    const apiKey = defaultClient.authentications['api-key'];
    apiKey.apiKey = process.env.BREVO_API_KEY;

    const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    sendSmtpEmail.subject = 'MFA Token';
    sendSmtpEmail.htmlContent = `<html><body><h1>Su codigo de verificacion es: ${mfaToken}</h1></body></html>`;
    sendSmtpEmail.sender = {
      email: 'miguelgar56382gar@gmail.com',
      name: 'Miguel',
    };
    sendSmtpEmail.to = [{ email }];

    try {
      await apiInstance.sendTransacEmail(sendSmtpEmail);
      return { message: 'MFA token enviado' };
    } catch (error) {
      console.error(error);
    }
  }

  async validateMfaToken(email: string, mfaToken: string) {
    const user = await this.userRepository.findOne({
      where: { email, mfaToken },
    });

    if (
      !user ||
      user.mfaToken !== mfaToken ||
      new Date() > new Date(user.mfaTokenExpiresAt)
    ) {
      throw new BadRequestException(
        'Codigo de verificacion invalido o expirado',
      );
    }

    return { message: 'MFA token verificado' };
  }

  private handleDBError(error: any, email: string): never {
    if (error.code === '23505') {
      throw new BadRequestException(
        `El usuario con el email ${email} ya existe`,
      );
    }
    throw new BadRequestException('Error');
  }
}

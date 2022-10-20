import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { AuthDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable({})
export class AuthService {
  constructor(private prismaService: PrismaService) {}
  async signup(dto: AuthDto) {
    //generate password hash
    const hash = await argon.hash(dto.password);

    //save new user in db
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;

      //return the saved user
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials Already Used');
        }
      }
      throw error;
    }
  }

  async login(dto: AuthDto) {
    //find user by email
    const user = await this.prismaService.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    //throw exception if user doesnt exist
    if (!user) throw new ForbiddenException('User not found');
    //compare password
    const pwMatches = await argon.verify(user.hash, dto.password);
    //exception if password doesnt match
    if (!pwMatches) throw new ForbiddenException('Password Incorrect');
    //return user
    delete user.hash;
    return user;
  }
}

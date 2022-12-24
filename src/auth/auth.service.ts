import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { sign } from 'jsonwebtoken';
import { Model } from 'mongoose';
import { User } from 'src/users/models/users.model';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('User')
    private readonly usersModel: Model<User>,
  ) {}

  public async createAccessToken(userId: string): Promise<string> {
    const payload = {
      userId,
    };
    const secret = process.env.JWT_SECRET;
    const signOptions = {
      expiresIn: process.env.JWT_EXPIRATION,
    };

    return sign(payload, secret, signOptions);
  }

  public async validateUser(userId: string): Promise<User> {
    const user = await this.usersModel.findOne({
      _id: userId,
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }
}

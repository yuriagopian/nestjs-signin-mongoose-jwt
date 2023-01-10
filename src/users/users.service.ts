import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { AuthService } from 'src/auth/auth.service';
import { SigninDto } from './dto/signin.dto';
import { SignupDto } from './dto/singup.dto';
import { User } from './models/users.model';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel('User')
    private readonly usersModel: Model<User>,
    private readonly authService: AuthService,
  ) {}

  public async signup(signupDto: SignupDto): Promise<User> {
    const user = new this.usersModel(signupDto);
    return user.save();
  }

  public async signin(
    signinDto: SigninDto,
  ): Promise<{ name: string; jwtToken: string; email: string }> {
    const user = await this.findByEmail(signinDto.email);

    const match = await this.checkPassword(signinDto.password, user);

    if (!match) {
      throw new BadRequestException('Invalid credentials');
    }

    const jwtToken = await this.authService.createAccessToken(user._id);

    return { name: user.name, jwtToken, email: user.email };
  }

  private async findByEmail(email: string): Promise<User> {
    const user = await this.usersModel.findOne({ email });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  private async checkPassword(password: string, user: User): Promise<boolean> {
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      throw new UnauthorizedException();
    }

    return match;
  }
}

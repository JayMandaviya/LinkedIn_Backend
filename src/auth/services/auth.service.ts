import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { Observable, from, of } from 'rxjs';
import { map, switchMap, catchError } from 'rxjs/operators';
import { JwtService } from '@nestjs/jwt';

import { User } from '../models/user.interface';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../models/user.entity';
import { Repository, FindOneOptions } from 'typeorm';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    private jwtService: JwtService,
  ) {}

  hashPassword(password: string): Observable<string> {
    return from(bcrypt.hash(password, 12));
  }

  registerAccount(user: User): Observable<User> {
    const { firstName, lastName, email, password } = user;

    return this.hashPassword(password).pipe(
      switchMap((hashedPassword: string) => {
        return from(
          this.userRepository.save({
            firstName,
            lastName,
            email,
            password: hashedPassword,
          }),
        ).pipe(
          map((user: User) => {
            delete user.password;
            return user;
          }),
        );
      }),
    );
  }

  // validateUser(email: string, password: string): Observable<User> {
  //   return from(
  //     this.userRepository.findOne(
  //       { email },
  //       {
  //         select: ['id', 'firstName', 'lastName', 'email', 'password', 'role'],
  //       },
  //     ),
  //   ).pipe(
  //     switchMap((user: User) => {
  //       if (!user) {
  //         throw new HttpException(
  //           { status: HttpStatus.FORBIDDEN, error: 'Invalid Credentials' },
  //           HttpStatus.FORBIDDEN,
  //         );
  //       }
  //       return from(bcrypt.compare(password, user.password)).pipe(
  //         map((isValidPassword: boolean) => {
  //           if (isValidPassword) {
  //             delete user.password;
  //             return user;
  //           }
  //         }),
  //       );
  //     }),
  //   );
  // }

  validateUser(email: string, password: string): Observable<User> {
    return from(
      this.userRepository.find({
        where: { email },
        select: ['id', 'firstName', 'lastName', 'email', 'password', 'role'],
      }),
    ).pipe(
      switchMap((users: User[]) => {
        const user = users[0];
        if (!user) {
          throw new HttpException(
            { status: HttpStatus.FORBIDDEN, error: 'Invalid Credentials' },
            HttpStatus.FORBIDDEN,
          );
        }
        return from(bcrypt.compare(password, user.password)).pipe(
          map((isValidPassword: boolean) => {
            if (isValidPassword) {
              delete user.password;
              return user;
            }
          }),
        );
      }),
    );
  }

  login(user: User): Observable<string> {
    const { email, password } = user;
    return this.validateUser(email, password).pipe(
      switchMap((user: User) => {
        if (user) {
          return from(this.jwtService.signAsync({ user }));
        }
      }),
    );
  }

  getJwtUser(jwt: string): Observable<User | null> {
    return from(this.jwtService.verifyAsync(jwt)).pipe(
      map(({ user }: { user: User }) => {
        return user;
      }),
      catchError(() => {
        return of(null);
      }),
    );
  }


}

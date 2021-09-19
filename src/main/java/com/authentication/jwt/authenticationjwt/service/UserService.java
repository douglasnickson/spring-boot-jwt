package com.authentication.jwt.authenticationjwt.service;

import java.util.List;

import com.authentication.jwt.authenticationjwt.model.Role;
import com.authentication.jwt.authenticationjwt.model.User;

public interface UserService {
  User saveUser(User user);

  Role saveRole(Role role);

  void addRoleToUser(String username, String role);

  User getUser(String username);
  
  List<User> getUsers();
}

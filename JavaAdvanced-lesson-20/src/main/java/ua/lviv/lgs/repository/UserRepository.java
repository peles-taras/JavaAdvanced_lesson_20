package ua.lviv.lgs.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import ua.lviv.lgs.domain.User;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
User findByUserName(String userName);
}

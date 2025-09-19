package com.my131.backend.service;

import com.my131.backend.dto.PostRequest;
import com.my131.backend.dto.PostResponse;
import com.my131.backend.entity.Post;
import com.my131.backend.entity.User;
import com.my131.backend.repository.PostRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
@Transactional
public class PostService {
    private final PostRepository postRepository;
    private final AuthenticationService authenticationService;

    public PostResponse createPost(PostRequest request) {
        User currentUser = authenticationService.getCurrentUser();
        Post post = Post.builder()
                .content(request.getContent())
                .user(currentUser)
                .deleted(false)
                .build();

        post = postRepository.save(post);
        return PostResponse.fromEntity(post);
    }

    @Transactional(readOnly = true)
    public Page<PostResponse> getAllPosts(Pageable pageable) {
        authenticationService.getCurrentUser();
        Page<Post> posts = postRepository.findAllActive(pageable);
        return posts.map(PostResponse::fromEntity);
    }
}

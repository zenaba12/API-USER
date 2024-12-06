<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Encoder\PasswordHasherInterface;


class UserController extends AbstractController
{
    // #[Route('/users', name: 'get_users', methods: ['GET'])]
    public function index(EntityManagerInterface $em): JsonResponse
    {
        $users = $em->getRepository(User::class)->findAll();
        
        // Exclure le mot de passe et autres données sensibles
        $usersData = array_map(fn($user) => [
            'id' => $user->getId(),
            'userName' => $user->getuserName(),
        
            'email' => $user->getEmail(),
            'roles' => $user->getRoles(),
        ], $users);
        
        return $this->json($usersData);
    }

    // #[Route('/users/{id}', name: 'get_user_by_id', methods: ['GET'])]
    public function show(int $id, EntityManagerInterface $em): JsonResponse
    {
        $user = $em->getRepository(User::class)->find($id);
        if (!$user) {
            return $this->json(['error' => 'User not found'], 404);
        }

        // Exclure le mot de passe et autres données sensibles
        $userData = [
            'id' => $user->getId(),
            'userName' => $user->getuserName(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles(),
        ];

        return $this->json($userData);
    }

    // #[Route('/users', name: 'create_user', methods: ['POST'])]
    public function createUser(Request $request, EntityManagerInterface $em, UserPasswordHasherInterface $passwordHasher): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        // Validation des données d'entrée
        if (!isset($data['userName'],  $data['email'], $data['password'])) {
            return $this->json(['error' => 'Missing required fields'], 400);
        }

        $user = new User();
        $user->setuserName($data['userName']);
        $user->setEmail($data['email']);
        $user->setPassword($passwordHasher->hashPassword($user, $data['password']));
        $user -> setRoles (['ROLE_USER']);

        $em->persist($user);
        $em->flush();

    

        return $this->json($user, 201);
    }

    // #[Route('/users/{id}', name: 'update_user', methods: ['PUT'])]
    public function updateUser(int $id, Request $request, EntityManagerInterface $em, UserPasswordHasherInterface $passwordHasher): JsonResponse
    {
        $user = $em->getRepository(User::class)->find($id);
        if (!$user) {
            return $this->json(['error' => 'User not found'], 404);
        }

        $data = json_decode($request->getContent(), true);

        // Mettre à jour les informations uniquement si elles sont présentes dans la demande
        if (isset($data['userName'])) {
            $user->setuserName($data['userName']);
        }
        if (isset($data['email'])) {
            $user->setEmail($data['email']);
        }
        if (isset($data['password'])) {
            $user->setPassword($passwordHasher->hashPassword($user, $data['password']));
        }

        $em->flush();

        // Exclure le mot de passe et retourner les données mises à jour
        $userData = [
            'id' => $user->getId(),
            'userName' => $user->getuserName(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles(),
        ];

        return $this->json($userData);
    }

    // #[Route('/users/{id}', name: 'delete_user', methods: ['DELETE'])]
    public function deleteUser(int $id, EntityManagerInterface $em): JsonResponse
    {
        $user = $em->getRepository(User::class)->find($id);
        if (!$user) {
            return $this->json(['error' => 'User not found'], 404);
        }

        $em->remove($user);
        $em->flush();

        // Retourner une réponse vide avec code 400
        return $this->json([], 400);
    }
    public function login(
        Request $request, 
        JWTTokenManagerInterface $JWTManager, 
        UserPasswordHasherInterface $passwordHasher, 
        EntityManagerInterface $em
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
    
        $username = $data['username'];
        $password = $data['password'];
    
        // Recherche de l'utilisateur
        $user = $em->getRepository(User::class)->findOneBy(['username' => $username]);
    
        if (!$user || !$passwordHasher->isPasswordValid($user, $password)) {
            return new JsonResponse(['message' => 'Invalid credentials'], 401);
        }
    
        // Création du JWT
        $token = $JWTManager->create($user);
    
        return new JsonResponse(['token' => $token]);
    }
    
}


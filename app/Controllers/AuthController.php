<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use App\Models\Users;
use CodeIgniter\HTTP\ResponseInterface;

class AuthController extends BaseController
{
    public function register()
    {
        $userModel = new Users();

        // Validasi input
        $validationRules = [
            'name'     => 'required|min_length[3]|max_length[100]',
            'email'    => 'required|valid_email|is_unique[users.email]',
            'password' => 'required|min_length[6]'
        ];

        if (!$this->validate($validationRules)) {
            return $this->response->setJSON([
                'status'  => ResponseInterface::HTTP_BAD_REQUEST,
                'message' => $this->validator->getErrors()
            ])->setStatusCode(ResponseInterface::HTTP_BAD_REQUEST);
        }

        // Hash password
        $hashedPassword = password_hash($this->request->getPost('password'), PASSWORD_DEFAULT);

        // Simpan data pengguna
        $userData = [
            'name'     => $this->request->getPost('name'),
            'email'    => $this->request->getPost('email'),
            'password' => $hashedPassword
        ];

        $userModel->insert($userData);

        return $this->response->setJSON([
            'status'  => ResponseInterface::HTTP_CREATED,
            'message' => 'User registered successfully'
        ])->setStatusCode(ResponseInterface::HTTP_CREATED);
    }

    public function login()
    {
        $userModel = new Users();

        // Ambil input
        $email    = $this->request->getPost('email');
        $password = $this->request->getPost('password');

        // Validasi input
        if (!$email || !$password) {
            return $this->response->setJSON([
                'status'  => ResponseInterface::HTTP_BAD_REQUEST,
                'message' => 'Email and password are required'
            ])->setStatusCode(ResponseInterface::HTTP_BAD_REQUEST);
        }

        // Cari pengguna berdasarkan email
        $user = $userModel->where('email', $email)->first();

        if (!$user || !password_verify($password, $user['password'])) {
            return $this->response->setJSON([
                'status'  => ResponseInterface::HTTP_UNAUTHORIZED,
                'message' => 'Invalid email or password'
            ])->setStatusCode(ResponseInterface::HTTP_UNAUTHORIZED);
        }

        // Return response sukses
        return $this->response->setJSON([
            'status'  => ResponseInterface::HTTP_OK,
            'message' => 'Login successful',
            'user'    => [
                'id'    => $user['id'],
                'name'  => $user['name'],
                'email' => $user['email']
            ]
        ])->setStatusCode(ResponseInterface::HTTP_OK);
    }
}

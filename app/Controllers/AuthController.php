<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use App\Models\Users;
use CodeIgniter\HTTP\ResponseInterface;

class AuthController extends BaseController
{
    public function register()
    {
        $json = $this->request->getJSON();
        // log_message('debug', json_encode($this->request->getPost()));
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
        $hashedPassword = password_hash($json->password, PASSWORD_DEFAULT);

        // Simpan data pengguna
        $userData = [
            'name'     => $json->name,
            'email'    => $json->email,
            'password' => $hashedPassword
        ];

        $data = $userModel->insert($userData);

        return $this->response->setJSON([
            'status'  => ResponseInterface::HTTP_CREATED,
            'message' => 'User registered successfully',
            'log' => $json
        ])->setStatusCode(ResponseInterface::HTTP_CREATED);
    }

    public function login()
    {
        $json = $this->request->getJSON();
        $userModel = new Users();

        // Ambil input
        $email    = $json->email;
        $password = $json->password;


        // Hash password
        $hashedPassword = password_hash($json->password, PASSWORD_DEFAULT);

        // Validasi input
        if (!$email || !$password) {
            return $this->response->setJSON([
                'status'  => ResponseInterface::HTTP_BAD_REQUEST,
                'message' => 'Email and password are required'
            ])->setStatusCode(ResponseInterface::HTTP_BAD_REQUEST);
        }

        // Cari pengguna berdasarkan email
        $user = $userModel->where('email', $email)->first();

        if (!$user || $hashedPassword == $user['password']) {
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

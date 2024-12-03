import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { Usuario } from '../models/Usuario';
import { Notificacao } from '../models/Notificacao';
import DOMPurify from 'isomorphic-dompurify'; // Usar DOMPurify para sanitizar entradas de usuário no backend


const SECRET_KEY = 'token_helo'; 

const sanitizeInput = (input: any) => {
    if (typeof input === 'string') {
        return DOMPurify.sanitize(input);
    }
    if (typeof input === 'object') {
        for (const key in input) {
            input[key] = sanitizeInput(input[key]);
        }
    }
    return input;
};


export const ping = (req: Request, res: Response) => {
    res.json({ pong: true });
};

// Cadastro de usuários
export const cadastrarUsuario = async (req: Request, res: Response) => {
    const { nome, email, senha, disciplina } = sanitizeInput(req.body); // Sanitiza entradas
    if (email && senha && nome && disciplina) {
        let usuarioExistente = await Usuario.findOne({ where: { email } });
        if (!usuarioExistente) {
            let novoUsuario = await Usuario.create({ email, senha, nome, disciplina });
            res.status(201).json({
                message: "Usuário cadastrado com sucesso.",
                novoUsuario
            });
        } else {
            res.status(400).json({ error: 'E-mail já existe.' });
        }
    } else {
        res.status(400).json({ error: 'E-mail e/ou senha não enviados.' });
    }
};


export const fazerLogin = async (req: Request, res: Response) => {
    const { email, senha } = sanitizeInput(req.body); // Sanitiza entradas
    if (email && senha) {
        let usuario = await Usuario.findOne({ where: { email, senha } });
        if (usuario) {
            // Gera um token JWT para o usuário
            const token = jwt.sign(
                { id: usuario.id, email: usuario.email }, // Payload
                SECRET_KEY, 
                { expiresIn: '1h' } 
            );
            return res.status(200).json({ status: true, token });
        } else {
            return res.status(401).json({ status: false, message: 'Credenciais inválidas!' });
        }
    }
    res.status(400).json({ status: false, message: 'Email e/ou senha não enviados.' });
};

// Listar todos os usuários
export const listarTodosUsuarios = async (req: Request, res: Response) => {
    let usuarios = await Usuario.findAll();
    res.json({ usuarios });
};

// Listar todos os emails de usuários
export const listarEmails = async (req: Request, res: Response) => {
    let usuarios = await Usuario.findAll();
    let listaEmails: string[] = usuarios.map(usuario => usuario.email);
    res.json({ listaEmails });
};

// Atualizar usuário
export const atualizarUsuario = async (req: Request, res: Response) => {
    const { id } = req.params;
    const valores = sanitizeInput(req.body); // Sanitiza entradas

    if (Object.values(valores).some(valor => valor === null || valor === '')) {
        return res.status(400).json({ mensagem: 'Os dados enviados estão incompletos.', status: '400' });
    }

    try {
        const usuarioEncontrado = await Usuario.findOne({ where: { id } });

        if (!usuarioEncontrado) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado.', status: '404' });
        }

        await Usuario.update(valores, { where: { id } });
        const usuarioAtualizado = await Usuario.findOne({ where: { id } });
        res.status(200).json({ mensagem: 'Usuário atualizado com sucesso.', status: '200', usuarioAtualizado });
    } catch (error) {
        res.status(500).json({ mensagem: 'Erro ao atualizar usuário.', status: '500', error });
    }
};

// Deletar usuário
export const deletarUsuario = async (req: Request, res: Response) => {
    const { id } = req.params;

    try {
        const user = await Usuario.findByPk(id);
        if (user) {
            const deletedUserName = user.nome;
            await user.destroy();
            res.status(200).json({ message: `Usuário ${deletedUserName} foi removido com sucesso.`, status: '200' });
        } else {
            res.status(404).json({ message: `Usuário com ID ${id} não encontrado.`, status: '404' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Ocorreu um erro ao remover o usuário.', status: '500', error });
    }
};

// Buscar usuário pelo ID
export const pegarUsuarioPeloId = async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
        const usuario = await Usuario.findByPk(id);
        res.status(200).json({ message: `Usuário encontrado`, status: '200', usuario });
    } catch (error) {
        res.status(500).json({ message: 'Erro interno no servidor.', status: '500', error });
    }
};

// Mostrar notificação
export const mostrarNotificacao = async (req: Request, res: Response) => {
    let notificacao = await Notificacao.findAll();
    res.json({ notificacao });
};

// Atualizar notificação
export const atualizarNotificacao = async (req: Request, res: Response) => {
    const { titulo, corpo, mostrar } = sanitizeInput(req.body); // Sanitiza entradas

    if (titulo && corpo && mostrar) {
        try {
            const notificacaoExistente = await Notificacao.findOne();
            if (notificacaoExistente) {
                notificacaoExistente.titulo = titulo;
                notificacaoExistente.corpo = corpo;
                notificacaoExistente.mostrar = mostrar;
                await notificacaoExistente.save();
                res.status(200).json({ message: "Notificação atualizada com sucesso.", notificacao: notificacaoExistente });
            } else {
                res.status(404).json({ error: 'Notificação não encontrada.' });
            }
        } catch (error) {
            res.status(500).json({ error: 'Erro interno no servidor.' });
        }
    } else {
        res.status(400).json({ error: 'Campos inválidos.' });
    }
};

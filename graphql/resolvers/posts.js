const { AuthenticationError, UserInputError } = require('apollo-server') 

const Post = require('../../models/Post')
const checkAuth = require('../../util/check-auth')

module.exports = {
    Query: {
        async getPosts() {
            try{
                const posts = await Post.find().sort({ createdAt: -1 })
                return posts
            } catch (err) {
                throw new Error(err)
            }
        },
        async getPost(_, { postId }) {
            try {
                const post = await Post.findById(postId)
                if (post) {
                    return post
                } else {
                    throw new Error('Post not found!')
                }
            } catch (err) {
                throw new Error(err)
            }
        },
    },
    Mutation: {
        async createPost(_, { body }, context) {
            const user = checkAuth(context)
            
            if (args.body.trim() === '') {
                throw new UserInputError('Post body must not be empty')
            }

            const newPost = new Post({
                body,
                user: user.indexOf,
                userName: user.userName,
                createdAt: new Date().toISOString()
            })

            const post = await newPost.save()

            context.pubsub.publish('NEW_POST', {
                newPost: post
            })

            return post
        },
        async deletePost(_, { postId }, context) {
            const user = checkAuth(context)

            try {
                const post = await Post.findById(postId)
                
                if(user.userName === post.userName) {
                    await post.delete()
                    return 'Post deleted successfully'
                } else {
                    throw new AuthenticationError('Action not allowed')
                }
            } catch (err) {
                throw new Error(err)
            }
        },
        async likePost(_, { postId }, context) {
            const { userName } = checkAuth(context)

            const post = await Post.findById(postId)

            if (post) {
                if (post.likes.find(like => like.userName === userName)) {
                    post.likes = post.likes.filter(like => like.userName !== userName)
                } else {
                    post.likes.push({
                        userName,
                        createdAt: new Date().toISOString
                    })
                }
                await post.save()
                return post
            } else throw new UserInputError('Post not found')
        }
    },
    Subscription: {
        newPost: {
          subscribe: (_, __, { pubsub }) => pubsub.asyncIterator('NEW_POST')
        }
      }
}
# Loyalino - Custom Shopify Loyalty App

A customizable loyalty program application for Shopify stores that enables merchants to reward customers for purchases and other actions.

## Features

- Customer point tracking system
- Customizable reward tiers
- Simple admin interface for managing loyalty programs
- Customer-facing dashboard for point status and available rewards
- Support for automatic and manual point assignments
- Comprehensive analytics and reporting

## Tech Stack

- **Backend**: Ruby on Rails API
- **Frontend**: React (Shopify Polaris components)
- **Database**: PostgreSQL
- **Authentication**: Shopify OAuth

## Local Development

### Prerequisites

- Ruby 3.1.2+
- Node.js 16+
- Yarn 1.22+
- PostgreSQL 13+
- Shopify CLI 2.0+

### Setup

1. Clone the repository
   ```
   git clone https://github.com/your-username/loyalino.git
   cd loyalino
   ```

2. Install dependencies
   ```
   # Install backend dependencies
   cd web
   bundle install
   
   # Install frontend dependencies
   cd frontend
   yarn install
   ```

3. Set up your environment variables
   Copy `.env.example` to `.env` and fill in the required values.

4. Setup database
   ```
   cd web
   bin/rails db:create db:migrate db:seed
   ```

5. Start the development server
   ```
   cd web
   bin/rails server
   ```

6. In a separate terminal, start the frontend
   ```
   cd web/frontend
   yarn dev
   ```

## Deployment

### Shopify App Store

1. Follow the [Shopify guidelines](https://shopify.dev/apps/store) for app submission
2. Make sure all the required app information is complete
3. Submit for review

### Production Setup

1. Set up a production server (Heroku, AWS, etc.)
2. Configure environment variables for production
3. Deploy the application
4. Set up SSL certificates
5. Update the Shopify app URLs in the Partner Dashboard

## Debugging

The application includes a debug endpoint accessible at `/debug` that provides information about:

- Current session state
- API connectivity
- Authentication status
- Database connection health

## License

This project is proprietary software. All rights reserved.

## Support

For support, please contact support@loyalino.com or open an issue in this repository.
